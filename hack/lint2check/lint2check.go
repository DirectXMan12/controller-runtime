/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"os"
	"encoding/json"
	"fmt"
	"os/exec"
	"go/token"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-github/v25/github"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	globalLog = zap.Logger(true)
	log = globalLog.WithName("main")
)

const (
	DefaultChecksOutPath = "/workspace/checks/run.json"

	DefaultKeyFile = "/var/run/secrets/github/appskey.pem"
	DefaultAppIDFile = "/var/run/secrets/github/appid.json"

)

type lintResults struct {
	Issues []issue
	Report reportData
}

type issue struct {
	FromLinter string
	Text string
	Pos token.Position

	LineRange *lineRange
	Replacement *replacement
}

type replacement struct {
	NeedOnlyDelete bool
	NewLines []string
}

type lineRange struct {
	From, To int
}

type reportData struct {
	Warnings []warning
	Linters []linterData
	Error string
}

type linterData struct {
	Name string
	Enabled bool
}

type warning struct {
	Tag string
	Text string
}

func loadJSON(log logr.Logger, files map[string]interface{}) bool {
	for path := range files {
		log := log.WithValues("path", path)
		body, err := os.Open(path)
		if err != nil {
			log.Error(err, "unable to read input file")
			return false
		}
		defer body.Close()
		out := files[path]
		if err := json.NewDecoder(body).Decode(&out); err != nil {
			log.Error(err, "unable to decode JSON")
			return false
		}
		files[path] = out
	}
	return true
}

func main() {
	if !lintAndSubmit() {
		// Don't exit with failure until we figure out how to deal with failure paths in a task
	}
}

func lintAndSubmit() (succeeded bool) {
	succeeded = true

	var checkRun github.CheckRun
	if !loadJSON(log, map[string]interface{}{
		DefaultChecksOutPath: &checkRun,
	}) {
		succeeded = false
	} else {
		if err := runLints(&checkRun); err != nil {
			// don't return immediately -- write things first
			succeeded = false
		}
	}

	defUnknownErr := "**unknown error while linting**"
	if checkRun.Output.Title == nil || checkRun.Output.Summary == nil {
		checkRun.Output.Title = &defUnknownErr
		checkRun.Output.Summary = &defUnknownErr
	}

	log.Info("saving check run results", "results", checkRun)
	outFile, err := os.Create(DefaultChecksOutPath)
	if err != nil {
		log.Error(err, "unable to open checks file for writing", "path", DefaultChecksOutPath)
		return false
	}
	defer outFile.Close()

	if err := json.NewEncoder(outFile).Encode(checkRun); err != nil {
		log.Error(err, "unable to write check run to file")
	}

	log.Info("done")
	return succeeded
}

func runLints(checkRun *github.CheckRun) error {
	// TODO(directxman12); there's probably a way to run this directly,
	// but this is easiest for now
	args := append([]string{"run", "--out-format", "json"}, os.Args[1:]...)
	lintOutRaw, checkErrRaw := exec.Command("golangci-lint", args...).Output()
	// don't return early, since we might get results
	if checkErrRaw != nil {
		if exitErr, isExitErr := checkErrRaw.(*exec.ExitError); isExitErr {
			log.Error(checkErrRaw, "issue running checks", "stderr", exitErr.Stderr)
		} else {
			log.Error(checkErrRaw, "issue running checks")
		}
	}

	// set the completed time so we have a timestamp in case of error return
	checkRun.CompletedAt = &github.Timestamp{Time: time.Now()}

	var lintRes lintResults
	if err := json.Unmarshal(lintOutRaw, &lintRes); err != nil {
		defFailure := "failure"
		checkRun.Conclusion = &defFailure
		return err
	}

	conclusion := "success"
	summary := fmt.Sprintf("%v problems\n\n%v warnings", len(lintRes.Issues), len(lintRes.Report.Warnings))
	switch {
	case len(lintRes.Issues) > 0 || checkErrRaw != nil || lintRes.Report.Error != "":
		conclusion = "failure"
	case len(lintRes.Report.Warnings) > 0:
		conclusion = "neutral"
	}
	checkRun.Conclusion = &conclusion

	if lintRes.Report.Error != "" {
		summary += fmt.Sprintf("\n\nError running linters: %s", lintRes.Report.Error)
	}
	defTitle := "Linter Runs"
	checkRun.Output.Title = &defTitle
	checkRun.Output.Summary = &summary

	var linterLines []string
	for _, linter := range lintRes.Report.Linters {
		if !linter.Enabled {
			continue
		}
		linterLines = append(linterLines, "- "+linter.Name)
	}
	details := fmt.Sprintf("## Enabled Linters\n\n%s\n", strings.Join(linterLines, "\n"))

	if len(lintRes.Report.Warnings) > 0 {
		var warningLines []string
		for _, warning := range lintRes.Report.Warnings {
			warningLines = append(warningLines, fmt.Sprintf("- *%s*: %s", warning.Tag, warning.Text))
		}
		details += fmt.Sprintf("## Warnings\n\n%s\n", strings.Join(warningLines, "\n"))
	}

	checkRun.Output.Text = &details

	var annotations []*github.CheckRunAnnotation
	for i := range lintRes.Issues {
		// don't take references to the iteration variable
		issue := lintRes.Issues[i]
		defFailure := "failure"
		issueDetails := ""

		if issue.Replacement != nil {
			if issue.Replacement.NeedOnlyDelete {
				issueDetails = "\n\n*delete these lines*"
			} else {
				issueDetails = fmt.Sprintf("\n\n*replace these lines with*:\n\n```go\n%s\n```", strings.Join(issue.Replacement.NewLines, "\n"))
			}
		}

		msg := issue.Text
		msg += issueDetails

		annot := &github.CheckRunAnnotation{
			Path: &issue.Pos.Filename,
			AnnotationLevel: &defFailure,
			Message: &msg,
			Title: &issue.FromLinter,
			RawDetails: nil,
		}

		if issue.LineRange != nil {
			annot.StartLine = &issue.LineRange.From
			annot.EndLine = &issue.LineRange.To
		} else {
			annot.StartLine = &issue.Pos.Line
			annot.EndLine = &issue.Pos.Line
			// TODO(directxman12): go-github doesn't support columns yet,
			// re-add this when they do
			// annot.StartColumn = &issue.Pos.Column
			// annot.EndColumn = &issue.Pos.Column
		}

		annotations = append(annotations, annot)
	}

	checkRun.Output.Annotations = annotations
	return checkErrRaw
}
