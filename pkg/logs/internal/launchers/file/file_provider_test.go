// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/DataDog/datadog-agent/pkg/logs/config"
	"github.com/DataDog/datadog-agent/pkg/logs/internal/util"
	"github.com/DataDog/datadog-agent/pkg/logs/sources"
	"github.com/DataDog/datadog-agent/pkg/logs/status"
)

type ProviderTestSuite struct {
	suite.Suite
	testDir    string
	filesLimit int
}

// newLogSources returns a new log source initialized with the right path.
func (suite *ProviderTestSuite) newLogSources(path string) []*sources.LogSource {
	return []*sources.LogSource{sources.NewLogSource("", &config.LogsConfig{Type: config.FileType, Path: path})}
}

func (suite *ProviderTestSuite) SetupTest() {
	suite.filesLimit = 3

	// Create temporary directory
	var err error
	suite.testDir = suite.T().TempDir()

	// Create directory tree:
	err = os.Mkdir(filepath.Join(suite.testDir, "1"), os.ModePerm)
	suite.NoError(err)

	_, err = os.Create(filepath.Join(suite.testDir, "1", "1.log"))
	suite.NoError(err)

	_, err = os.Create(filepath.Join(suite.testDir, "1", "2.log"))
	suite.NoError(err)

	_, err = os.Create(filepath.Join(suite.testDir, "1", "3.log"))
	suite.NoError(err)

	err = os.Mkdir(filepath.Join(suite.testDir, "2"), os.ModePerm)
	suite.NoError(err)

	_, err = os.Create(filepath.Join(suite.testDir, "2", "1.log"))
	suite.NoError(err)

	_, err = os.Create(filepath.Join(suite.testDir, "2", "2.log"))
	suite.NoError(err)
}

func (suite *ProviderTestSuite) TearDownTest() {
	status.Clear()
}

func (suite *ProviderTestSuite) TestFilesToTailReturnsSpecificFile() {
	testLogFile := filepath.Join(suite.testDir, "1", "1.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogFile)
	util.CreateSources(logSources)
	files := fileProvider.filesToTail(logSources)

	suite.Equal(1, len(files))
	suite.False(files[0].IsWildcardPath)
	suite.Equal(testLogFile, files[0].Path)
	suite.Equal(make([]string, 0), logSources[0].Messages.GetMessages())
}

func (suite *ProviderTestSuite) TestFilesToTailReturnsAllFilesFromDirectory() {
	testLogFile := filepath.Join(suite.testDir, "1", "*.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogFile)
	status.InitStatus(util.CreateSources(logSources))
	files := fileProvider.filesToTail(logSources)

	suite.Equal(3, len(files))
	suite.True(files[0].IsWildcardPath)
	suite.True(files[1].IsWildcardPath)
	suite.True(files[2].IsWildcardPath)
	suite.Equal(filepath.Join(suite.testDir, "1", "3.log"), files[0].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "2.log"), files[1].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "1.log"), files[2].Path)
	suite.Equal([]string{"3 files tailed out of 3 files matching"}, logSources[0].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (3) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)
}

func (suite *ProviderTestSuite) TestCollectFilesWildcardFlag() {
	// with wildcard

	testLogFile := filepath.Join(suite.testDir, "1", "*.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogFile)
	files, err := fileProvider.collectFiles(logSources[0])
	suite.NoError(err, "searching for files in this directory shouldn't fail")
	for _, file := range files {
		suite.True(file.IsWildcardPath, "this file has been found with a wildcard pattern.")
	}

	// without wildcard

	testLogFile = filepath.Join(suite.testDir, "1", "1.log")
	fileProvider = newFileProvider(suite.filesLimit)
	logSources = suite.newLogSources(testLogFile)
	files, err = fileProvider.collectFiles(logSources[0])
	suite.NoError(err, "searching for files in this directory shouldn't fail")
	for _, file := range files {
		suite.False(file.IsWildcardPath, "this file has not been found using a wildcard pattern.")
	}
}

func (suite *ProviderTestSuite) TestFilesToTailReturnsAllFilesFromAnyDirectoryWithRightPermissions() {
	testLogPath := filepath.Join(suite.testDir, "*", "*1.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogPath)
	util.CreateSources(logSources)
	files := fileProvider.filesToTail(logSources)

	suite.Equal(2, len(files))
	suite.True(files[0].IsWildcardPath)
	suite.True(files[1].IsWildcardPath)
	suite.Equal(filepath.Join(suite.testDir, "2", "1.log"), files[0].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "1.log"), files[1].Path)
	suite.Equal([]string{"2 files tailed out of 2 files matching"}, logSources[0].Messages.GetMessages())
}

func (suite *ProviderTestSuite) TestFilesToTailReturnsSpecificFileWithWildcard() {
	testLogPath := filepath.Join(suite.testDir, "1", "?.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogPath)
	status.InitStatus(util.CreateSources(logSources))
	files := fileProvider.filesToTail(logSources)

	suite.Equal(3, len(files))
	suite.True(files[0].IsWildcardPath)
	suite.True(files[1].IsWildcardPath)
	suite.True(files[2].IsWildcardPath)
	suite.Equal(filepath.Join(suite.testDir, "1", "3.log"), files[0].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "2.log"), files[1].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "1.log"), files[2].Path)
	suite.Equal([]string{"3 files tailed out of 3 files matching"}, logSources[0].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (3) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)
}

func (suite *ProviderTestSuite) TestWildcardPathsAreSorted() {
	filesLimit := 6
	testLogPath := filepath.Join(suite.testDir, "*", "*.log")
	fileProvider := newFileProvider(filesLimit)
	logSources := suite.newLogSources(testLogPath)
	files := fileProvider.filesToTail(logSources)
	suite.Equal(5, len(files))
	for i := 0; i < len(files); i++ {
		suite.Assert().True(files[i].IsWildcardPath)
	}
	suite.Equal(filepath.Join(suite.testDir, "1", "3.log"), files[0].Path)
	suite.Equal(filepath.Join(suite.testDir, "2", "2.log"), files[1].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "2.log"), files[2].Path)
	suite.Equal(filepath.Join(suite.testDir, "2", "1.log"), files[3].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "1.log"), files[4].Path)
}

func (suite *ProviderTestSuite) TestNumberOfFilesToTailDoesNotExceedLimit() {
	testLogPath := filepath.Join(suite.testDir, "*", "*.log")
	fileProvider := newFileProvider(suite.filesLimit)
	logSources := suite.newLogSources(testLogPath)
	status.InitStatus(util.CreateSources(logSources))
	files := fileProvider.filesToTail(logSources)
	suite.Equal(suite.filesLimit, len(files))
	suite.Equal([]string{"3 files tailed out of 5 files matching"}, logSources[0].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (3) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)
}

func (suite *ProviderTestSuite) TestAllWildcardPathsAreUpdated() {
	filesLimit := 2
	fileProvider := newFileProvider(filesLimit)
	logSources := []*sources.LogSource{
		sources.NewLogSource("", &config.LogsConfig{Type: config.FileType, Path: filepath.Join(suite.testDir, "1", "*.log")}),
		sources.NewLogSource("", &config.LogsConfig{Type: config.FileType, Path: filepath.Join(suite.testDir, "2", "*.log")}),
	}
	status.InitStatus(util.CreateSources(logSources))
	files := fileProvider.filesToTail(logSources)
	suite.Equal(2, len(files))
	suite.Equal([]string{"2 files tailed out of 3 files matching"}, logSources[0].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (2) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)
	suite.Equal([]string{"0 files tailed out of 2 files matching"}, logSources[1].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (2) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)

	suite.NoError(os.Remove(filepath.Join(suite.testDir, "1", "2.log")))
	suite.NoError(os.Remove(filepath.Join(suite.testDir, "1", "3.log")))
	suite.NoError(os.Remove(filepath.Join(suite.testDir, "2", "2.log")))

	files = fileProvider.filesToTail(logSources)
	suite.Equal(2, len(files))
	suite.Equal([]string{"1 files tailed out of 1 files matching"}, logSources[0].Messages.GetMessages())

	suite.Equal([]string{"1 files tailed out of 1 files matching"}, logSources[1].Messages.GetMessages())
	suite.Equal(
		[]string{
			"The limit on the maximum number of files in use (2) has been reached. Increase this limit (thanks to the attribute logs_config.open_files_limit in datadog.yaml) or decrease the number of tailed file.",
		},
		status.Get().Warnings,
	)

	suite.NoError(os.Remove(filepath.Join(suite.testDir, "2", "1.log")))
	files = fileProvider.filesToTail(logSources)
	suite.Equal(1, len(files))
	suite.Equal([]string{"1 files tailed out of 1 files matching"}, logSources[0].Messages.GetMessages())

	suite.Equal([]string{"0 files tailed out of 0 files matching"}, logSources[1].Messages.GetMessages())
}

func (suite *ProviderTestSuite) TestExcludePath() {
	filesLimit := 6
	testLogPath := filepath.Join(suite.testDir, "*", "*.log")
	excludePaths := []string{filepath.Join(suite.testDir, "2", "*.log")}
	fileProvider := newFileProvider(filesLimit)
	logSources := []*sources.LogSource{
		sources.NewLogSource("", &config.LogsConfig{Type: config.FileType, Path: testLogPath, ExcludePaths: excludePaths}),
	}

	files := fileProvider.filesToTail(logSources)
	suite.Equal(3, len(files))
	for i := 0; i < len(files); i++ {
		suite.Assert().True(files[i].IsWildcardPath)
	}
	suite.Equal(filepath.Join(suite.testDir, "1", "3.log"), files[0].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "2.log"), files[1].Path)
	suite.Equal(filepath.Join(suite.testDir, "1", "1.log"), files[2].Path)
}

func TestProviderTestSuite(t *testing.T) {
	suite.Run(t, new(ProviderTestSuite))
}
