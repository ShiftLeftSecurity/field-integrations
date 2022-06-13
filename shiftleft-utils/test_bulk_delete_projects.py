from unittest import TestCase
from pytest_httpserver import HTTPServer

from bulk_delete_projects import _delete_project


class Test(TestCase):
    def test__delete_project(self):
        with HTTPServer() as httpserver:
            def fail_if_not_confirmation(req):
                if req.data != b"confirmation_token":
                    print(F"expected data to be confirmation_token but is {req.data}")
                    raise Exception("no confirmation token present")

            resource_url = httpserver.url_for("/resource")
            # set up the server to serve /foobar with the json
            httpserver.expect_request("/resource", method="DELETE", data=b"confirmation_token"). \
                respond_with_handler(fail_if_not_confirmation)
            httpserver.expect_request("/resource", method="DELETE"). \
                respond_with_json({"response": "confirmation_token"})

            try:
                _delete_project("somecookie", resource_url)
            except Exception as e:
                print(F"failed with {e}")
                self.fail()
            httpserver.check_handler_errors()
