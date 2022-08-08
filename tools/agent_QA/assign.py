import sys
import os
from dotenv import load_dotenv
from trello import TrelloClient
from random import shuffle

splitup_threshold = 10

if len(sys.argv) < 3:
    print("Usage: python assign.py <trello board id> <comma-separated-candidate-assignees>")
    exit(1)

board_id = sys.argv[1]
trello_names = sys.argv[2].split(",")

load_dotenv()
api_key = os.getenv('API_KEY')
api_secret = os.getenv('API_SECRET')
org_id = os.getenv('ORG_ID')
dry_run = os.getenv('DRY_RUN') != None
if not api_key or not api_secret or not org_id:
    print("Missing required env vars")
    exit(1)

client = TrelloClient(api_key=api_key, api_secret=api_secret)
board = client.get_board(board_id)
lists = board.get_lists(None)


assignee_idx = 0
potential_assignees = [client.get_member(username) for username in trello_names]
shuffle(potential_assignees)

print(f"Assigning all cards from board {board_id} \"{board.name}\" to these folks '{trello_names}'")

print("Adding all members to board first")
for member in potential_assignees:
    print(f"Adding {member.full_name} to board {board.name}")

    if not dry_run:
        # TODO Only add members who are not "me"
        # (ie, the currently authenticated user running this script)
        # If you add the "me" user, it demotes them from owner
        # to regular member
        board.add_member(member)

def assign(card, member):
    print(f"Assigning card '{card.name}' to '{member.full_name}'")
    if not dry_run:
        card.assign(member.id)

# Split up cards column-by-column
for l in lists:
    print(f"Assigning list {l.name} ")
    if l.cardsCnt() > splitup_threshold:
        # This list needs to be sub-divided
        # So start a new assignee tracker
        sub_assignee_idx = assignee_idx
        for idx, card in enumerate(l.list_cards()):
            # Every 10 cards, switch up the assignee
            if idx % splitup_threshold == 0:
                sub_assignee_idx = (sub_assignee_idx + 1) % len(potential_assignees)
            assign(card, potential_assignees[sub_assignee_idx])

        # Use sub_assignee_idx to advance for a fair-er card distribution
        assignee_idx = (sub_assignee_idx + 1) % len(potential_assignees)
    else:
        # This list is short enough for a single human
        # to own the entire list
        assignee = potential_assignees[assignee_idx]
        for card in l.list_cards():
            assign(card, assignee)

        assignee_idx = (assignee_idx + 1) % len(potential_assignees)
    print("")

print("Done.")

