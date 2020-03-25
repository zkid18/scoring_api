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

# Maybe we neeed to inherint from  class other than object
# Can we step back from the template

class CharField(object):
    def __init__(self,required, nullable, name):
        self.required = required
        self.nullable = nullable
        self._value = None
        self.name = name

    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value == None

    @value.setter
    def value(self, value):
        if ((self.required) and (value == None)):
            # AttributeError("{} required".format(field_name))
            logging.error("No {} provided".format(self.name))
        
        if ((not self.nullable) and (value == '')):
            # AttributeError("Login required".format(field_name))
            logging.error("No {} provided".format(self.name))
        
        self._value = value


class ArgumentsField(object):
    def __init__(self,required, nullable):
        self._argument_dict = None
        self.required = required
        self.nullable = nullable

    @property
    def argument_dict(self):
        return self._argument_dict
    
    @argument_dict.setter
    def argument_dict(self, argument_dict):
        self._argument_dict = argument_dict
    


class EmailField(CharField):
    def __init__(self,required, nullable, name):
        CharField.__init__(self, required, nullable, name)

    @property
    def value(self):
        return super().value
    
    @property 
    def is_exist(self):
        return super().is_exist()
    
    @value.setter
    def value(self, value):
        if '@' not in value:
            # NameError('Not a valid email name')
            logging.error("Email {} is not valid".format(self.name))
        else:
            super(EmailField, EmailField).value.__set__(self, value)
        

class PhoneField(object):
    def __init__(self, required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
    
    @property
    def value(self):
        return self._value
    
    @property 
    def is_exist(self):
        return self._value == None
    
    @value.setter
    def value(self, value):
        if (len(str(value)) != 11) and (str(value)[0]) != 7:
            # NameError('Not a valid phone name')
            logging.error("Phone {} is not valid".format(value))
    
        self._value = value


class DateField(object):
    def __init__(self, required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable


class BirthDayField(object):
    # can be inherite from DateFiled
    def __init__(self,required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
    
    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value == None
    
    @value.setter
    def value(self, value):
        lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")
        birthday = re.search(lineformat,value)
        birthday.groupdict()

        if ((self.required) and (value == None)):
            # AttributeError("{} required".format(field_name))
            logging.error("Birthday is required")
        
        if ((not self.nullable) and (value == '')):
            # AttributeError("Login required".format(field_name))
            logging.error("Bithday can'r be null")

        if (2020-int(birthday['year']) > 70):
            logging.error("Invalid birthday is provided")
        
        self._value = birthday



class GenderField(object):
    def __init__(self,required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable

    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value == None
    
    @value.setter
    def value(self, value):
        if value > 1:
            logging.error("Invalid gender {} provided")
        self._value = value


class ClientIDsField(object):
    def __init__(self, required):
        print("client_id", required)


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    intersts = get_interests(store=None, cid=1)


class OnlineScoreRequest(object):

    '''
    * phone - строка или число, длиной 11, начинается с 7, опционально, может быть пустым
    * email - строка, в которой есть @, опционально, может быть пустым
    * first_name - строка, опционально, может быть пустым
    * last_name - строка, опционально, может быть пустым
    * birthday - дата в формате DD.MM.YYYY, с которой прошло не больше 70 лет, опционально, может быть пустым
    * gender - число 0, 1 или 2, опционально, может быть пустым
    '''

    first_name = CharField(required=False, nullable=True, name='First name')
    last_name = CharField(required=False, nullable=True, name='Last name')
    email = EmailField(required=False, nullable=True, name = 'Email')
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        self.first_name.value = arguments['first_name']
        self.last_name.value = arguments['last_name']
        self.email.value = arguments['email']
        self.phone.value = arguments['phone']
        self.birthday.value = arguments['birthday']
        self.gender.value = arguments['gender']

    @property
    def is_valid(self):
        if (self.first_name.is_exist or self.last_name.is_exist) or (self.phone.is_exist or self.email.is_exist) or (self.gender or self.birthday):
            logging.info('Valid')
            return True
        else:
            logging.error('Not valid')
            return False

    def get_score(self):
        score = get_score(store=None, phone=self.phone, email=self.email, birthday=self.birthday, gender=self.gender, first_name=self.first_name, last_name=self.last_name)
        return score


class MethodRequest(object):
    '''
    Obiazatelnyi methods
    '''

    account = CharField(required=False, nullable=True, name='Account')
    login = CharField(required=True, nullable=True, name='Login')
    token = CharField(required=True, nullable=True, name='Token')
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False, name='Method')

    
    def __init__(self, request):
        self.account.value = request['account']
        self.login.value = request['login']
        self.token.value = request['token']
        self.arguments.argument_dict = request['arguments']
        self.method.value = request['method']


    def send_request(self):
        if self.method.value == 'online_score':
            online_score_request = OnlineScoreRequest(self.arguments.argument_dict)
            score = online_score_request.get_score()
            return score
        if self.method.value == 'clients_interests':
            client_intersts_request = ClientsInterestsRequest(self.arguments)
    
    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN



def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512((request.account.value + request.login.value + SALT).encode('utf-8')).hexdigest()
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
    #ctx['has'] = not_null_filed
    method_request = MethodRequest(request['body'])
    if check_auth(method_request) == False:
        code = FORBIDDEN
        response = ERRORS[FORBIDDEN]
    else:
        score = method_request.send_request()
        response, code = score, OK
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
            # data_string - string of argument
            # then create json
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
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
