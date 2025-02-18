import json
import os
import subprocess
from collections import defaultdict

from .common.gitlab import Gitlab, get_gitlab_token
from .types import FailedJobReason, Test


def get_failed_jobs(project_name, pipeline_id):
    gitlab = Gitlab(project_name=project_name, api_token=get_gitlab_token())

    # gitlab.all_jobs yields a generator, it needs to be converted to a list to be able to
    # go through it twice
    jobs = list(gitlab.all_jobs(pipeline_id))

    # Get instances of failed jobs
    failed_jobs = {job["name"]: [] for job in jobs if job["status"] == "failed"}

    # Group jobs per name
    for job in jobs:
        if job["name"] in failed_jobs:
            failed_jobs[job["name"]].append(job)

    # There, we now have the following map:
    # job name -> list of jobs with that name, including at least one failed job

    final_failed_jobs = []
    for job_name, jobs in failed_jobs.items():
        # We sort each list per creation date
        jobs.sort(key=lambda x: x["created_at"])
        # We truncate the job name to increase readability
        job_name = truncate_job_name(job_name)
        # Check the final job in the list: it contains the current status of the job
        # This excludes jobs that were retried and succeeded
        final_status = {
            "name": job_name,
            "id": jobs[-1]["id"],
            "stage": jobs[-1]["stage"],
            "status": jobs[-1]["status"],
            "allow_failure": jobs[-1]["allow_failure"],
            "url": jobs[-1]["web_url"],
            "retry_summary": [job["status"] for job in jobs],
            "failure_type": get_job_failure_reason(gitlab.job_log(jobs[-1]["id"])),
        }

        # Also exclude jobs allowed to fail
        if final_status["status"] == "failed" and not final_status["allow_failure"]:
            final_failed_jobs.append(final_status)

    return final_failed_jobs


def get_job_failure_reason(job_log):
    infra_failure_logs = [
        # Gitlab errors while pulling image
        "no basic auth credentials (manager.go:203:0s)",
        "net/http: TLS handshake timeout (manager.go:203:10s)",
        "Failed to pull image with policy \"always\": error pulling image configuration",
        # docker / docker-arm runner init failures
        "Docker runner job start script failed",
        "A disposable runner accepted this job, while it shouldn't have. Runners are meant to run just one job and be terminated.",
        # k8s Gitlab runner init failures
        "Job failed (system failure): prepare environment: waiting for pod running: timed out waiting for pod to start",
        # kitchen tests Azure VM allocation failures
        "Allocation failed. We do not have sufficient capacity for the requested VM size in this region.",
    ]

    for log in infra_failure_logs:
        if log in job_log:
            return FailedJobReason.INFRA_FAILURE
    return FailedJobReason.JOB_FAILURE


def truncate_job_name(job_name, max_char_per_job=48):
    # Job header should be before the colon, if there is no colon this won't change job_name
    truncated_job_name = job_name.split(":")[0]
    # We also want to avoid it being too long
    truncated_job_name = truncated_job_name[:max_char_per_job]
    return truncated_job_name


def read_owners(owners_file):
    from codeowners import CodeOwners

    with open(owners_file, 'r') as f:
        return CodeOwners(f.read())


def get_failed_tests(project_name, job, owners_file=".github/CODEOWNERS"):
    gitlab = Gitlab(project_name=project_name, api_token=get_gitlab_token())
    owners = read_owners(owners_file)
    test_output = gitlab.artifact(job["id"], "test_output.json", ignore_not_found=True)
    failed_tests = {}  # type: dict[tuple[str, str], Test]
    if test_output:
        for line in test_output.iter_lines():
            json_test = json.loads(line)
            if 'Test' in json_test:
                name = json_test['Test']
                package = json_test['Package']
                action = json_test["Action"]

                if action == "fail":
                    # Ignore subtests, only the parent test should be reported for now
                    # to avoid multiple reports on the same test
                    # NTH: maybe the Test object should be more flexible to incorporate
                    # subtests? This would require some postprocessing of the Test objects
                    # we yield here to merge child Test objects with their parents.
                    if '/' in name:  # Subtests have a name of the form "Test/Subtest"
                        continue
                    failed_tests[(package, name)] = Test(owners, name, package)
                elif action == "pass" and (package, name) in failed_tests:
                    print(f"Test {name} from package {package} passed after retry, removing from output")
                    del failed_tests[(package, name)]

    return failed_tests.values()


def find_job_owners(failed_jobs, owners_file=".gitlab/JOBOWNERS"):
    owners = read_owners(owners_file)
    owners_to_notify = defaultdict(list)

    for job in failed_jobs:
        # Exclude jobs that failed due to infrastructure failures
        if job["failure_type"] == FailedJobReason.INFRA_FAILURE:
            continue
        job_owners = owners.of(job["name"])
        # job_owners is a list of tuples containing the type of owner (eg. USERNAME, TEAM) and the name of the owner
        # eg. [('TEAM', '@DataDog/agent-platform')]

        for kind, owner in job_owners:
            if kind == "TEAM":
                owners_to_notify[owner].append(job)

    return owners_to_notify


def base_message(header):
    return """{header} pipeline <{pipeline_url}|{pipeline_id}> for {commit_ref_name} failed.
{commit_title} (<{commit_url}|{commit_short_sha}>) by {author}""".format(  # noqa: FS002
        header=header,
        pipeline_url=os.getenv("CI_PIPELINE_URL"),
        pipeline_id=os.getenv("CI_PIPELINE_ID"),
        commit_ref_name=os.getenv("CI_COMMIT_REF_NAME"),
        commit_title=os.getenv("CI_COMMIT_TITLE"),
        commit_url="{project_url}/commit/{commit_sha}".format(  # noqa: FS002
            project_url=os.getenv("CI_PROJECT_URL"), commit_sha=os.getenv("CI_COMMIT_SHA")
        ),
        commit_short_sha=os.getenv("CI_COMMIT_SHORT_SHA"),
        author=get_git_author(),
    )


def get_git_author():
    return (
        subprocess.check_output(["git", "show", "-s", "--format='%an'", "HEAD"])
        .decode('utf-8')
        .strip()
        .replace("'", "")
    )


def send_slack_message(recipient, message):
    subprocess.run(["postmessage", recipient, message], check=True)
