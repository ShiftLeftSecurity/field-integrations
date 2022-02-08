package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

type Output struct {
	Scan     interface{} `json:"scan"`
	Packages []Finding   `json:"packages"`
}

func main() {
	orgID := os.Getenv("SHIFTLEFT_ORG_ID")
	token := os.Getenv("SHIFTLEFT_ACCESS_TOKEN")
	if orgID == "" {
		log.Fatal("missing org ID (set SHIFTLEFT_ORG_ID env var)")
	}
	if token == "" {
		log.Fatal("missing token (set SHIFTLEFT_ACCESS_TOKEN env var)")
	}

	appID := flag.String("app", "", "App ID")
	flag.Parse()

	if *appID == "" {
		log.Println("missing app ID")
		flag.Usage()
		return
	}

	output := Output{}

	packages := map[string]Finding{}
	// Query packages
	url := fmt.Sprintf("https://app.shiftleft.io/api/v4/orgs/%s/apps/%s/findings?type=package&per_page=249", orgID, *appID)
	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(fmt.Errorf("build findings request: %w", err))
		}
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("X-Shiftleft-Feature-Flag", "sca-all-languages")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(fmt.Errorf("do request: %w", err))
		}

		findingsResp := FindingsResponse{}
		err = json.NewDecoder(resp.Body).Decode(&findingsResp)
		if err != nil {
			log.Fatal(fmt.Errorf("decode response: %w", err))
		}
		output.Scan = findingsResp.Response.Scan
		for _, pkg := range findingsResp.Response.Findings {
			packages[pkg.GetTagValue("package_url")] = pkg
		}
		url = findingsResp.NextPage
	}

	// Query reachable oss vulns
	url = fmt.Sprintf("https://app.shiftleft.io/api/v4/orgs/%s/apps/%s/findings?type=oss_vuln&per_page=249&finding_tags=reachability=reachable", orgID, *appID)
	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(fmt.Errorf("build findings request: %w", err))
		}
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("X-Shiftleft-Feature-Flag", "sca-all-languages")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(fmt.Errorf("do request: %w", err))
		}

		findingsResp := FindingsResponse{}
		err = json.NewDecoder(resp.Body).Decode(&findingsResp)
		if err != nil {
			log.Fatal(fmt.Errorf("decode response: %w", err))
		}

		for _, vuln := range findingsResp.Response.Findings {
			purl := vuln.GetTagValue("package_url")
			ossID := vuln.GetTagValue("oss_internal_id")
			if ossID == "" {
				continue
			}

			pkg := packages[purl]
			pkg.ReachableOSSVulns = append(pkg.ReachableOSSVulns, vuln)

			packages[purl] = pkg
		}

		url = findingsResp.NextPage
	}

	// Query unreachable oss vulns
	url = fmt.Sprintf("https://app.shiftleft.io/api/v4/orgs/%s/apps/%s/findings?type=oss_vuln&per_page=249&finding_tags=reachability=unreachable", orgID, *appID)
	for url != "" {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Fatal(fmt.Errorf("build findings request: %w", err))
		}
		req.Header.Add("Authorization", "Bearer "+token)
		req.Header.Add("X-Shiftleft-Feature-Flag", "sca-all-languages")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatal(fmt.Errorf("do request: %w", err))
		}

		findingsResp := FindingsResponse{}
		err = json.NewDecoder(resp.Body).Decode(&findingsResp)
		if err != nil {
			log.Fatal(fmt.Errorf("decode response: %w", err))
		}

		for _, vuln := range findingsResp.Response.Findings {
			purl := vuln.GetTagValue("package_url")
			ossID := vuln.GetTagValue("oss_internal_id")
			if ossID == "" {
				continue
			}

			pkg := packages[purl]
			pkg.UnreachableOSSVulns = append(pkg.UnreachableOSSVulns, vuln)

			packages[purl] = pkg
		}

		url = findingsResp.NextPage
	}

	for key, pkg := range packages {
		reachable := len(pkg.ReachableOSSVulns)
		unreachable := len(pkg.UnreachableOSSVulns)
		pkg.TotalReachableOSSVulns = &reachable
		pkg.TotalUnreachableOSSVulns = &unreachable
		packages[key] = pkg
	}

	for _, pkg := range packages {
		output.Packages = append(output.Packages, pkg)
	}
	outputJSON, err := json.Marshal(output)
	if err != nil {
		log.Fatal(fmt.Errorf("marshal output: %w", err))
	}

	// Print the output
	fmt.Println(string(outputJSON))
}

type FindingsResponse struct {
	OK       bool `json:"ok"`
	Response struct {
		Scan     interface{} `json:"scan"`
		Findings []Finding   `json:"findings"`
	} `json:"response"`
	NextPage string `json:"next_page"`
}

type Finding struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Details     interface{} `json:"details"`
	Type        string      `json:"type"`
	Tags        []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`

	// For this script
	ReachableOSSVulns        []Finding `json:"reachable_oss_vulns,omitempty"`
	UnreachableOSSVulns      []Finding `json:"unreachable_oss_vulns,omitempty"`
	TotalReachableOSSVulns   *int      `json:"total_reachable_oss_vulns,omitempty"`
	TotalUnreachableOSSVulns *int      `json:"total_unreachable_oss_vulns,omitempty"`
}

func (f *Finding) GetTagValue(key string) string {
	for _, t := range f.Tags {
		if t.Key == key {
			return t.Value
		}
	}
	return ""
}
