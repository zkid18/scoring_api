#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import re
import base64
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from scoring import get_score, get_interests

"""
A 422 status code occurs when a request is well-formed, 
however, due to semantic errors it is unable to be processe

The 400 (Bad Request) status code indicates that the server cannot or will not process the request
due to something that is perceived to be a client error 
(e.g., malformed request syntax, invalid request message framing, or deceptive request routing).
"""


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

VALIDATED_FIELD_OK = "OK"

# Maybe we neeed to inherint from  class other than object
# Can we step back from the template


class BaseField(object):
    '''
    BaseFiled class - interface class for Field object
    '''
    def __init__(self, required, nullable):
        '''
        The __init__ method takes the following parameters:
        1. reuqired - Boolean value indicated that value is required
        2. nullable - Boolena value indicated that value can be nullable
        3. name - String value for field name
        '''

        self.required = required
        self.nullable = nullable
        self.value = None

    def __set_name__(self, owner, name):
        self.name = '_' + name

    def __get__(self, instance, cls):
        return getattr(instance, self.name, self.value)
    
    def _validate_value(self, value):
        '''
        Can be overwitten by child classes
        '''
        status_message = VALIDATED_FIELD_OK
        return status_message

    def __set__(self, instance, value):
        '''
        1. Check if value is None but is required
        2. Validate value based on the field value
        '''
        if value is None:
            if self.required:
                raise TypeError("{} is required".format(self.name))
            else:
                pass
        else:
            status_message = self._validate_value(value)
            if status_message == VALIDATED_FIELD_OK:
                instance.__dict__[self.name] = value
            else:
                raise TypeError('Wrong type of {0}; Error description: {2}; The value {1}'\
                                .format(self.name, status_message, value))


class CharField(BaseField):
    '''
    Char filed class - BaseField implemenation for Char fields
    '''

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        validated_field_wrong = 'Only strings are accepted'
        valid_condition = isinstance(value, str)  
        return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong
    

class ArgumentsField(BaseField):
    '''
    ArgumentsField - class for argument field
    '''
    def __init__(self,required, nullable):
        '''
        The __init__ method takes the following parameters:
        1. reuqired - Boolean value indicated that value is required
        2. nullable - Boolena value indicated that value can be nullable
        3. name - String value for field name
        '''
        super().__init__(required, nullable)


class EmailField(CharField):
    '''
    Email Filed class - CharFiled class implemenation for email field
    '''
    def __init__(self,required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        '''
        * email - строка, в которой есть @, опционально, может быть пустым
        '''
        validated_field_wrong = 'The email field requires @'
        valid_condition = '@' in value
        return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong


class PhoneField(BaseField):
    '''
    PhoneField class - BaseField implemenation for phone field
    '''
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        '''
        * phone - строка или число, длиной 11, начинается с 7, опционально, может быть пустым
        '''
        validated_field_wrong = 'The phone field must start from 7 and contain 11 characters'
        valid_condition = (len(str(value)) == 11) and (str(value)[0]) == '7'
        return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong


class DateField(BaseField):
    '''
    DateField class - BaseField implemenation for dates field
    '''
    lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        valid_condition = re.search(self.lineformat, value) is not None
        validated_field_wrong = 'The date field format is dd.MM.Y'
        return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong


class BirthDayField(BaseField):
    '''
    BirthDayField class - BaseField implemenation for birthday field
    '''
    lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")

    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        birthday = re.search(self.lineformat, value)

        if birthday:
            birthday_dict = birthday.groupdict()
            valid_condition = (2020-int(birthday_dict['year']) < 70) or (len(birthday_dict) == 0)
            validated_field_wrong = 'The birthday is maximum 70 years old'
            return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong
        else:
            validated_field_wrong = 'The date field format is not dd.MM.Y'
            return False


class GenderField(BaseField):
    '''
    GenderField class - BaseField implemenation for birthday field
    '''
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value):
        '''
        * gender - число 0, 1 или 2, опционально, может быть пустым
        '''
        valid_condition = isinstance(value, int) and (value in [0,1,2])
        validated_field_wrong = 'The birthday is maximum 70 years old'
        return VALIDATED_FIELD_OK if valid_condition else validated_field_wrong


class ClientIDsField(BaseField):
    '''
    GenderField class - BaseField implemenation for clientsID field
    '''
    def __init__(self, required, nullable):
        super().__init__(required, nullable)

    def _validate_value(self, value_list):
        if not isinstance(value_list, list):
            validated_field_wrong = 'Input value is list'
            return validated_field_wrong
        elif len(value_list) == 0:
            validated_field_wrong =  'List is empty'
            return validated_field_wrong
        elif not (all(isinstance(x, int) for x in value_list)):
            validated_field_wrong =  'Only integrers id availbale'
            return validated_field_wrong

        return VALIDATED_FIELD_OK


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def __init__(self, arguments):
        self.client_ids = arguments.get('client_ids', None)
        self.date = arguments.get('date', None)
    
    def get_interests(self):
        interests_dict = {}
        for client in self.client_ids:
            interests_dict[client] = get_interests(store=None, cid=client)  
        return interests_dict


class OnlineScoreRequest(object):

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):

        self.first_name = arguments.get('first_name', None)
        self.last_name = arguments.get('last_name', None)
        self.email = arguments.get('email', None)
        self.phone = arguments.get('phone', None)
        self.birthday = arguments.get('birthday', None)
        self.gender = arguments.get('gender', None)

    @property
    def is_valid(self):
        if (self.last_name is not None and self.first_name is not None) or\
            (self.phone is not None and self.email is not None) or\
            (self.birthday is not None and self.gender is not None):
            logging.info('Valid')
            return True
        else:
            logging.exception('Not valid')
            return False

    def get_score(self):
        score = get_score(store=None, phone=self.phone, email=self.email, birthday=self.birthday, gender=self.gender, first_name=self.first_name, last_name=self.last_name)
        return score


class MethodRequest(object):
    '''
    Required methods
    '''
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):

        self.account = request.get('account', None)
        self.login = request.get('login', None)
        self.token = request.get('token', None)
        self.arguments = request.get('arguments', None)
        self.method = request.get('method', None)

    def _find_required_fields(self, request):
        # required_fields
        required_fields = []
        for key, value in request.__dict__.items():
            if not key.startswith('__'):
                try:
                    if value.required:
                        required_fields.append(key)
                except:
                    pass
        return required_fields


    def send_request(self, ctx):
        if self.method == 'online_score':
            try:
                online_score_request = OnlineScoreRequest(self.arguments)
            except TypeError as type_error:
                logging.exception("TypeError {}".format(type_error))
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
            
            clients_interests_field = [field.replace('_', '', 1) for field in online_score_request.__dict__]
            required_fields = self._find_required_fields(OnlineScoreRequest)
            ctx['has'] = clients_interests_field
            
            if self.is_admin:
                return {'score': 42}
            elif (len([field for field in required_fields if field not in clients_interests_field]) == 0) and online_score_request.is_valid:
                score = online_score_request.get_score()
                return {'score':score}
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        
        elif self.method == 'clients_interests':
            try:
                client_intersts_request = ClientsInterestsRequest(self.arguments)
            except TypeError as type_error:
                logging.exception("TypeError {}".format(type_error))
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}    
            
            clients_interests_field = [field.replace('_', '', 1) for field in client_intersts_request.__dict__]
            required_fields = self._find_required_fields(ClientsInterestsRequest)
            
            if len([field for field in required_fields if field not in clients_interests_field]) == 0:
                ctx['has'] = clients_interests_field
                interests = client_intersts_request.get_interests()
                ctx['nclients'] = len(client_intersts_request.client_ids)
                return interests
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        
        else:
            error = ERRORS[INVALID_REQUEST]
            return {'error': error}

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    '''
    requests - body requests:
    * account - строка, опционально, может быть пустым
    * login - строка, обязательно, может быть пустым
    * method - строка, обязательно, может быть пустым
    * token - строка, обязательно, может быть пустым
    * arguments - словарь (объект в терминах json), обязательно, может быть пустым
    '''
    try:
        method_request = MethodRequest(request['body'])
    except TypeError as type_error:
        logging.exception("TypeError {}".format(type_error))
        error = ERRORS[INVALID_REQUEST]
        return error, INVALID_REQUEST

    if check_auth(method_request) is False:
        return ERRORS[FORBIDDEN], FORBIDDEN

    else:
        result = method_request.send_request(ctx)
        code = INVALID_REQUEST if 'error' in result else OK
        response, code = result, code
        return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        '''
        Return random request_id that replicate the production
        '''
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string.decode())
        except:
            code = BAD_REQUEST

        if request:
            # extract path from the api
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        json_res = json.dumps(r)
        self.wfile.write(json_res.encode())
        return 


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
