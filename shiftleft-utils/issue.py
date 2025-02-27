# This file is part of Scan.

# Scan is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Scan is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Scan.  If not, see <https://www.gnu.org/licenses/>.

# Adapted from bandit/core

import io
import linecache

from six import moves

from joern2sarif.lib.logger import LOG


class Issue(object):
    def __init__(
        self,
        severity="LOW",
        confidence="HIGH",
        text="",
        ident=None,
        lineno=None,
        test_id="",
    ):
        self.severity = severity
        self.confidence = confidence
        if isinstance(text, bytes):
            text = text.decode("utf-8", "ignore")
        self.text = text
        self.short_description = ""
        self.cwe_category = ""
        self.owasp_category = ""
        self.code = ""
        self.ident = ident
        self.fname = ""
        self.test = ""
        self.test_id = test_id
        self.test_ref_url = None
        self.lineno = lineno
        self.linerange = []
        # Does the tool operate in snippet mode. Eg: gitleaks
        self.snippet_based = False
        self.line_hash = ""
        self.first_found = None
        self.tags = {}
        self.codeflows = []

    def __str__(self):
        return ("Issue: '%s' from %s:%s: Severity: %s Confidence: " "%s at %s:%i") % (
            self.text,
            self.test_id,
            (self.ident or self.test),
            self.severity,
            self.confidence,
            self.fname,
            self.lineno,
        )

    def __eq__(self, other):
        # if the issue text, severity, confidence, and filename match, it's
        # the same issue from our perspective
        match_types = [
            "text",
            "severity",
            "confidence",
            "fname",
            "test",
            "test_id",
            "line_hash",
        ]
        return all(
            getattr(self, field) == getattr(other, field) for field in match_types
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return id(self)

    def _get_code_line(self, fname, line):
        """Return the given line from the file. Handles any utf8 error from tokenize

        :param fname: File name
        :param line: Line number
        :return: Exact line as string
        """
        text = ""
        try:
            text = linecache.getline(fname, line)
        except UnicodeDecodeError:
            LOG.debug(
                f"Error parsing the file {fname} in utf-8. Falling to binary mode"
            )
            with io.open(fname, "rb") as fp:
                all_lines = fp.readlines()
                if line < len(all_lines):
                    text = all_lines[line]
        return text

    def get_code(self, max_lines=3, tabbed=False):
        """Gets lines of code from a file the generated this issue.

        :param max_lines: Max lines of context to return
        :param tabbed: Use tabbing in the output
        :return: strings of code
        """
        if not self.fname:
            return ""
        lines = []
        max_lines = max(max_lines, 1)
        if not self.snippet_based:
            lmin = max(1, self.lineno - max_lines // 2)
            lmax = lmin + len(self.linerange) + max_lines - 1

            tmplt = "%i\t%s" if tabbed else "%i %s"
            for line in moves.xrange(lmin, lmax):
                text = self._get_code_line(self.fname, line)
                if isinstance(text, bytes):
                    text = text.decode("utf-8", "ignore")

                if not len(text):
                    break
                lines.append(tmplt % (line, text))
            if lines:
                return "".join(lines)
            elif self.code:
                # Validate if the code snippet is in the right format
                orig_lines = self.code.split("\n")
                if orig_lines:
                    orig_first_line = orig_lines[0]
                    firstword = orig_first_line.split(" ", 1)[0]
                    if firstword and str(firstword).isdigit():
                        return self.code
                return ""
            else:
                return ""
        else:
            lineno = self.lineno
            try:
                tmplineno = 1
                with open(self.fname, mode="r") as fp:
                    for aline in fp:
                        if aline.strip() == self.code.strip():
                            lineno = tmplineno
                            # Fix the line number
                            self.lineno = lineno
                            break
                        tmplineno = tmplineno + 1
            except Exception as e:
                LOG.debug(e)
            tmplt = "%i\t%s" if tabbed else "%i %s"
            return tmplt % (lineno, self.code)

    def as_dict(self, with_code=True):
        """Convert the issue to a dict of values for outputting."""
        issue_text = self.text.encode("utf-8").decode("utf-8")
        # As per the spec text sentence should end with a period
        if not issue_text.endswith("."):
            issue_text = issue_text + "."
        if self.test:
            # Cleanup test names
            if self.test == "blacklist":
                self.test = "blocklist"
            if self.test == "whitelist":
                self.test = "allowlist"
            if "_" in self.test:
                self.test = self.test.replace("_", " ")
                # Title case small rule names
                tmpA = self.test.split(" ")
                if len(tmpA) < 3:
                    self.test = self.test.title()
        # Take the first line as short description
        if not self.short_description and issue_text:
            self.short_description = issue_text.split(". ")[0]
        out = {
            "filename": self.fname,
            "test_name": self.test,
            "title": self.title,
            "test_id": str(self.test_id),
            "test_ref_url": self.test_ref_url,
            "issue_severity": self.severity,
            "issue_confidence": self.confidence,
            "issue_text": issue_text,
            "line_number": self.lineno,
            "line_range": self.linerange,
            "first_found": self.first_found,
            "short_description": self.short_description,
            "cwe_category": self.cwe_category,
            "owasp_category": self.owasp_category,
            "tags": self.tags,
            "line_hash": self.line_hash,
            "codeflows": self.codeflows,
        }

        if with_code:
            out["code"] = self.get_code()
            # If the line number has changed since referring to the file
            # use the latest line number
            if self.lineno != out["line_number"]:
                out["line_number"] = self.lineno
        return out

    def norm_severity(self, severity):
        """Method to normalize severity and convert non-standard strings

        :param severity: String severity for the issue
        """
        severity = severity.upper()
        if severity == "ERROR" or severity == "SEVERITY_HIGH_IMPACT":
            return "CRITICAL"
        if (
            severity == "WARN"
            or severity == "WARNING"
            or severity == "SEVERITY_MEDIUM_IMPACT"
        ):
            return "MEDIUM"
        if severity == "INFO" or severity == "SEVERITY_LOW_IMPACT":
            return "LOW"
        return severity

    def find_severity(self, data):
        severity = "LOW"
        if "confidence" in data:
            severity = data["confidence"].upper()
        if "issue_severity" in data or "priority" in data:
            sev = data.get("issue_severity", data.get("priority"))
            severity = sev
            if isinstance(sev, int) or sev.isdigit():
                sev = int(sev)
                if sev <= 3:
                    severity = "LOW"
                elif sev <= 5:
                    severity = "MEDIUM"
                elif sev <= 8:
                    severity = "HIGH"
                elif sev > 8:
                    severity = "CRITICAL"
        if "severity" in data:
            severity = str(data["severity"]).upper()
        if "commit" in data:
            severity = "HIGH"
        return self.norm_severity(severity)

    def get_lineno(self, data):
        """Extract line number with any int conversion"""
        lineno = 1
        tmp_no = 1
        if "line_number" in data:
            tmp_no = data["line_number"]
        if str(tmp_no).isdigit():
            lineno = int(tmp_no)
        return lineno

    def get_test_id(self, data):
        """
        Method to retrieve test_id
        :param data:
        :return:
        """
        test_id = ""
        if "test_id" in data:
            test_id = data["test_id"]
        if "rule_id" in data:
            test_id = data["rule_id"]
        return test_id

    def from_dict(self, data, with_code=True):
        """Construct an issue from dictionary of values from the tools

        :param data: Data dictionary from the tools
        :param with_code: Boolean indicating if code snippet should get added
        """
        if "filename" in data:
            self.fname = data["filename"]
        self.severity = self.find_severity(data)
        if "issue_confidence" in data:
            self.confidence = data["issue_confidence"].upper()
        if "confidence" in data:
            self.confidence = data["confidence"].upper()
        if "issue_text" in data:
            self.text = data["issue_text"]
        if "description" in data:
            self.text = data["description"]
        if "short_description" in data:
            self.short_description = data["short_description"]
        if "cwe_category" in data:
            self.cwe_category = data["cwe_category"]
        if "owasp_category" in data:
            self.owasp_category = data["owasp_category"]
        if "title" in data:
            self.test = data["title"].split(":")[0]
            self.title = data["title"]
        self.test_id = self.get_test_id(data)
        if "link" in data:
            self.test_ref_url = data["link"]
        if "more_info" in data:
            self.test_ref_url = data["more_info"]
        self.lineno = self.get_lineno(data)
        if "first_found" in data:
            self.first_found = data["first_found"]
        if "tags" in data and isinstance(data["tags"], dict):
            self.tags = data["tags"]
        if "fingerprint" in data:
            self.line_hash = data["fingerprint"]
        if "codeflows" in data:
            self.codeflows = data["codeflows"]


def issue_from_dict(data):
    i = Issue()
    i.from_dict(data)
    return i
