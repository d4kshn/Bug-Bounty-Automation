package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/sw33tLie/bbscope/v2/pkg/platforms/bugcrowd"
)

type scopeElement struct {
	Target      string `json:"target"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type scopeDocument struct {
	URL        string         `json:"url"`
	InScope    []scopeElement `json:"in_scope"`
	OutOfScope []scopeElement `json:"out_of_scope"`
}

func fail(message string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", message, err)
	} else {
		fmt.Fprintln(os.Stderr, message)
	}
	os.Exit(1)
}

func main() {
	tokenFile := flag.String("token-file", "", "path to a file containing a Bugcrowd session cookie")
	handle := flag.String("handle", "", "Bugcrowd program handle or engagement path")
	list := flag.Bool("list", false, "list accessible bug-bounty program handles")
	flag.Parse()

	if *tokenFile == "" {
		fail("--token-file is required", nil)
	}
	contents, err := os.ReadFile(*tokenFile)
	if err != nil {
		fail("cannot read token file", err)
	}
	token := strings.TrimSpace(string(contents))
	if token == "" {
		fail("session cookie file is empty", nil)
	}

	encoder := json.NewEncoder(os.Stdout)
	if *list {
		handles, err := bugcrowd.GetProgramHandles(token, "bug_bounty", false)
		if err != nil {
			fail("Bugcrowd session/list request failed", err)
		}
		if err := encoder.Encode(handles); err != nil {
			fail("cannot encode program handles", err)
		}
		return
	}
	if *handle == "" {
		fail("exactly one of --handle or --list is required", nil)
	}

	program, err := bugcrowd.GetProgramScope(*handle, "all", token)
	if err != nil {
		fail("Bugcrowd session/scope request failed", err)
	}
	document := scopeDocument{URL: program.Url}
	for _, item := range program.InScope {
		document.InScope = append(document.InScope, scopeElement{
			Target: item.Target, Description: item.Description, Category: item.Category,
		})
	}
	for _, item := range program.OutOfScope {
		document.OutOfScope = append(document.OutOfScope, scopeElement{
			Target: item.Target, Description: item.Description, Category: item.Category,
		})
	}
	if err := encoder.Encode(document); err != nil {
		fail("cannot encode program scope", err)
	}
}
