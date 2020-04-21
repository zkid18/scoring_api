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


class BaseField(object):
    '''
    BaseFiled class - interface class for Field object
    '''
    __metaclass__  = abc.ABCMeta

    def __init__(self, required, nullable):
        '''
        The __init__ method takes the following parameters:
        1. reuqired - Boolean value indicated that value is required
        2. nullable - Boolena value indicated that value can be nullable
        '''

        self.required = required
        self.nullable = nullable

    @abc.abstractclassmethod
    def validate_value(self, value):
        pass
    

class CharField(BaseField):
    '''
    Char filed class - BaseField implemenation for Char fields
    '''

    def validate_value(self, value):
        validated_field_wrong = 'For char fields only strings are accepted'
        valid_condition = isinstance(value, str)  
        super().validate_value(value)
        if not valid_condition:
            raise TypeError(validated_field_wrong)
    

class ArgumentsField(BaseField):
    '''
    ArgumentsField - class for argument field
    '''

    def validate_value(self, value):
        super().validate_value(value)


class EmailField(CharField):
    '''
    Email Filed class - CharFiled class implemenation for email field
    '''

    def validate_value(self, value):
        '''
        * email - строка, в которой есть @, опционально, может быть пустым
        '''
        validated_field_wrong = 'The email field requires @'
        valid_condition = ('@' in value)
        super().validate_value(value)
        if not valid_condition:
            raise TypeError(validated_field_wrong)


class PhoneField(BaseField):
    '''
    PhoneField class - BaseField implemenation for phone field
    '''

    def validate_value(self, value):
        '''
        * phone - строка или число, длиной 11, начинается с 7, опционально, может быть пустым
        '''
        validated_field_wrong = 'The phone field must start from 7 and contain 11 characters'
        valid_condition = (len(str(value)) == 11) and (str(value)[0]) == '7'
        super().validate_value(value)
        if not valid_condition:
            raise TypeError(validated_field_wrong)


class DateField(BaseField):
    '''
    DateField class - BaseField implemenation for dates field
    '''
    lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")

    def validate_value(self, value):
        valid_condition = re.search(self.lineformat, value) is not None
        validated_field_wrong = 'The date field format is dd.MM.Y'
        super().validate_value(value)
        if not valid_condition:
            raise TypeError(validated_field_wrong)


class BirthDayField(BaseField):
    '''
    BirthDayField class - BaseField implemenation for birthday field
    '''
    lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")

    def validate_value(self, value):
        birthday = re.search(self.lineformat, value)
        super().validate_value(value)
        if birthday:
            birthday_dict = birthday.groupdict()
            valid_condition = (2020-int(birthday_dict['year']) < 70) or (len(birthday_dict) == 0)
            validated_field_wrong = 'The birthday is maximum 70 years old'
            if not valid_condition:
                raise TypeError(validated_field_wrong)           
        else:
            validated_field_wrong = 'The date field format is not dd.MM.Y'
            raise TypeError(validated_field_wrong)


class GenderField(BaseField):
    '''
    GenderField class - BaseField implemenation for birthday field
    '''

    def validate_value(self, value):
        '''
        * gender - число 0, 1 или 2, опционально, может быть пустым
        '''
        super().validate_value(value)
        if not isinstance(value, int):
            validated_field_wrong = 'For gender only integers are accepted'
            raise TypeError(validated_field_wrong)
        elif value not in [0,1,2]:
            validated_field_wrong = 'Only value in the range [0,1,2] are accepted'
            raise TypeError(validated_field_wrong)


class ClientIDsField(BaseField):
    '''
    GenderField class - BaseField implemenation for clientsID field
    '''
    def validate_value(self, value_list):
        super().validate_value(value_list)
        if not isinstance(value_list, list):
            validated_field_wrong = 'Input value is list'
            raise TypeError(validated_field_wrong) 
        elif len(value_list) == 0:
            validated_field_wrong =  'List is empty'
            raise TypeError(validated_field_wrong)
        elif not (all(isinstance(x, int) for x in value_list)):
            validated_field_wrong =  'Only integrers id availbale'
            raise TypeError(validated_field_wrong)


class RequestMeta(type):
    def __new__(cls, name, bases, attrs):
        fields = {key:field for key, field in attrs.items() if isinstance(field, BaseField)}
        for key in fields:
            del attrs[key]
        attrs['fields'] = fields
        return super().__new__(cls, name, bases, attrs)


class RequestBase(metaclass=RequestMeta):
    def __init__(self, body):
        self.request_body = body
        self.req_errors_count = 0
        self.non_null_fields = []

    def is_empty(self, name):
        return self.request_body.get(name, None) in (None, '', [], {}, ())

    def is_valid(self):
        self.validate()
        return self.req_errors_count == 0

    def validate(self):
        for name, field in self.fields.items():
            value = self.request_body.get(name)            
            if field.required and value is None:
                self.req_errors_count += 1
            elif value is not None:
                try:
                    field.validate_value(value)
                    self.non_null_fields.append(name)
                except TypeError as e:
                    logging.exception(e)
                    self.req_errors_count += 1
            setattr(self, name, value)


class ClientsInterestsRequest(RequestBase):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(RequestBase):

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super().validate()
        if (not self.is_empty('last_name') and not self.is_empty('first_name')) or\
            (not self.is_empty('phone') and not self.is_empty('email')) or\
            (not self.is_empty('birthday') and not self.is_empty('gender')):
            logging.info("Request is valid")
        else:
            logging.exception("Request is invalid. At least one pair should be set")
            self.req_errors_count += 1


class OnlineScoreRequestHandler:
    request_class = OnlineScoreRequest

    def get_response(self, request, store, context):
        r = self.request_class(request.arguments)
        if request.is_admin:
            return {'score': 42}
        elif r.is_valid():
            score = get_score(store, r.phone, r.email, r.birthday, r.gender, r.first_name, r.last_name)
            context['has'] = r.non_null_fields
            return {'score':score}
        else:
            return {'error': INVALID_REQUEST}


class ClientsInterestsRequestHandler:
    request_class = ClientsInterestsRequest

    def get_response(self, request, store, context):
        r = self.request_class(request.arguments)
        if r.is_valid():
            logging.info("request is valid")
            interst_dict = {cid:get_interests(store, cid) for cid in r.client_ids}
            context['nclients'] = len(r.client_ids)
            return interst_dict
        else:
            logging.exception("request is invalid")
            return {'error': INVALID_REQUEST}


class MethodRequest(RequestBase):
    '''
    Required methods
    '''
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

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

    method_handler = {
        'online_score': OnlineScoreRequestHandler, 
        'clients_interests': ClientsInterestsRequestHandler
    }

    method_request = MethodRequest(request['body'])
    if method_request.is_valid():
        if check_auth(method_request):
            handler = method_handler[method_request.method]()
            response = handler.get_response(method_request, store, ctx)
            if 'error' not in response:
                return response, OK
            else:
                return ERRORS[INVALID_REQUEST], INVALID_REQUEST
        else:
            return ERRORS[FORBIDDEN], FORBIDDEN
    else:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST


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
