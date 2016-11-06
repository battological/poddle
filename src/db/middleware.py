from models import db


class DBConnectMiddleware(object):
    """
    Ensure database connection is opened and closed for each request.
    """

    def process_request(self, req, res):
        db.connect()

    def process_response(self, req, res, resource):
        if not db.is_closed():
            db.close()
