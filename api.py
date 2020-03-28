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

# Maybe we neeed to inherint from  class other than object
# Can we step back from the template

class BaseFiled(object):
    def __init__(self, required, nullable, name):
        self.required = required
        self.nullable = nullable
        self.name = name
        self._value = None
        self._is_wrong_type = False

    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value is not None

    
    @property
    def is_valid(self):
        '''
        1. Check field for nullability
        2. Check field for requirement property
        3. Check field for correct formati representation
        '''
        if ((not self.nullable) and (value == '')):
            # AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            # AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False

        elif self._is_wrong_type:
            return False

        return True

class CharField(object):
    def __init__(self,required, nullable, name):
        self.required = required
        self.nullable = nullable
        self._value = None
        self._is_wrong_type = False
        self.name = name

    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value != None

    @property
    def is_valid(self):
        if ((not self.nullable) and (value == '')):
            AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False

        elif self._is_wrong_type:
            return False

        else:
            return True
    
    @value.setter
    def value(self, value):
        if (isinstance(value, str)):
            self._value = value
        else:
            self._is_wrong_type = True
            AttributeError("{} is wrong type".format(self.name))
            logging.error("{} is wrong type".format(self.name))


class ArgumentsField(object):
    def __init__(self,required, nullable):
        self._argument_dict = None
        self.required = required
        self.nullable = nullable
        self.name = 'arguments'

    @property
    def argument_dict(self):
        return self._argument_dict
    
    @argument_dict.setter
    def argument_dict(self, argument_dict):
        self._argument_dict = argument_dict
    


class EmailField(CharField):
    def __init__(self,required, nullable):
        CharField.__init__(self, required, nullable, 'email')

    @property
    def value(self):
        return super().value
    
    @property 
    def is_exist(self):
        return super().is_exist
    
    @property
    def is_valid(self):
        return super().is_valid
    
    @value.setter
    def value(self, value):
        if '@' not in value:
            # NameError('Not a valid email name')
            self._is_wrong_type = True
            logging.error("Email {} is not valid".format(self.name))
        else:
            super(EmailField, EmailField).value.__set__(self, value)
        

class PhoneField(object):
    def __init__(self, required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
        self.name = 'phone'
        self._is_wrong_type = False

    
    @property
    def value(self):
        return self._value
    
    @property 
    def is_exist(self):
        return self._value != None

    @property
    def is_valid(self):
        if ((not self.nullable) and (value == '')):
            AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False
        
        elif self._is_wrong_type:
            return False

        else:
            return True
    
    @value.setter
    def value(self, value):
        if (len(str(value)) != 11) and (str(value)[0]) != 7:
            self._is_wrong_type = True
            # NameError('Not a valid phone name')
            logging.error("Phone {} is not valid".format(value))
        else:
            self._value = value


class DateField(object):
    def __init__(self, required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
        self.name = 'date'


class BirthDayField(object):
    # can be inherite from DateFiled
    def __init__(self,required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
        self.name = 'birthday'
        self._is_wrong_type = False
    
    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value != None
    
    @property
    def is_valid(self):
        if ((not self.nullable) and (value == '')):
            AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False
        
        elif self._is_wrong_type:
            return False
        
        else:
            return True

    @value.setter
    def value(self, value):
        lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")
        birthday = re.search(lineformat,value)
        birthday_dict = birthday.groupdict()

        if (2020-int(birthday_dict['year']) > 70):
            self._is_wrong_type = True
            AttributeError("Birthday data is required")
            logging.error("Invalid birthday is provided")
        
        else:
            self._value = birthday



class GenderField(object):
    def __init__(self,required, nullable):
        self._value = None
        self.required = required
        self.nullable = nullable
        self.name = 'gender'
        self._is_wrong_type = False


    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value != None

    @property
    def is_valid(self):
        if ((not self.nullable) and (value == '')):
            AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False

        elif self._is_wrong_type:
            return False
        
        else:
            return True
    
    @value.setter
    def value(self, value):
        if (value > 1) or (value<0):
            self._is_wrong_type = True
            logging.error("Invalid gender {} provided")
        else:
            self._value = value


class ClientIDsField(object):
    def __init__(self,required, nullable):
        self._value = None
        self._is_wrong_type = False
        self.required = required
        self.nullable = nullable
        self.name = 'client_ids'
    
    @property
    def value(self):
        return self._value

    @property 
    def is_exist(self):
        return self._value == None

    @property
    def is_valid(self):
        if ((not self.nullable) and (value == '')):
            AttributeError("{} is nullable".format(self.name))
            logging.error("{} nullable".format(self.name))
            return False
        
        elif (self.required) and (value == None):
            AttributeError("{} is required".format(self.name))
            logging.error("{} is nullable".format(self.name))
            return False
        
        elif self._is_wrong_type:
            return False
        
        else:
            return True
    
    @value.setter
    def value(self, value):
        if isinstance(value, list):
            self._value = value
        else:
            self._is_wrong_type = True
            logging.error("For ClientID list is required")




class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)
    _code = OK

    def __init__(self, argument):
        try:
            self.client_ids.value = argument['client_ids']
            self.date._value = argument['date']
        except Exception as e:
            if self.client_ids.required or \
            self.date.required:
                logging.exception("Error: %s" % e)
                self._code = INVALID_REQUEST

    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        fileds = [x.name for x in filter(lambda x: x.nullable==True,[self.client_ids, self.date])]
        return fileds

    @property
    def is_valid(self):
        return True

    def get_interests(self):
        interests_dict = {}
        for client in self.client_ids.value:
            interests_dict[client] = get_interests(store=None, cid=client)
        
        return interests_dict



class OnlineScoreRequest(object):

    '''
    * phone - строка или число, длиной 11, начинается с 7, опционально, может быть пустым
    * email - строка, в которой есть @, опционально, может быть пустым
    * first_name - строка, опционально, может быть пустым
    * last_name - строка, опционально, может быть пустым
    * birthday - дата в формате DD.MM.YYYY, с которой прошло не больше 70 лет, опционально, может быть пустым
    * gender - число 0, 1 или 2, опционально, может быть пустым
    '''

    first_name = CharField(required=False, nullable=True, name= 'first_name')
    last_name = CharField(required=False, nullable=True, name = 'last_name')
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)
    _code = OK

    def __init__(self, arguments):
        try:
            self.first_name.value = arguments['first_name']
            self.last_name.value = arguments['last_name']
            self.email.value = arguments['email']
            self.phone.value = arguments['phone']
            self.birthday.value = arguments['birthday']
            self.gender.value = arguments['gender']
        except Exception as e:
            if self.first_name.required or \
            self.last_name.required or \
            self.email.required or \
            self.phone.required or \
            self.birthday.required or \
            self.gender.required:
                logging.exception("Error: %s" % e)
                self._code = INVALID_REQUEST

    
    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        fileds = [x.name for x in filter(lambda x: x.nullable==True,[self.first_name, self.last_name, self.email, self.phone, self.email, self.birthday, self.gender])]
        return fileds


    @property
    def is_valid(self):
        if self.last_name.is_valid and self.first_name.is_valid \
        and self.phone.is_valid and self.email.is_valid \
        and self.birthday.is_valid and self.gender.is_valid:
            if (self.first_name.is_exist and self.last_name.is_exist) or (self.phone.is_exist and self.email.is_exist) or (self.gender.is_exist and self.birthday.is_exist):
                logging.info('Valid')
                return True
            else:
                logging.error('Not valid')
                return False
        else:
            return False

    def get_score(self):
        score = get_score(store=None, phone=self.phone, email=self.email, birthday=self.birthday, gender=self.gender, first_name=self.first_name, last_name=self.last_name)
        return score


class MethodRequest(object):
    '''
    Obiazatelnyi methods
    '''

    account = CharField(required=False, nullable=True, name= 'account')
    login = CharField(required=True, nullable=True, name= 'login')
    token = CharField(required=True, nullable=True, name= 'token')
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False, name = 'method')
    _code = OK
    _not_null = None
    
    def __init__(self, request):
        try:
            self.account.value = request['account']
            self.login.value = request['login']
            self.token.value = request['token']
            self.arguments.argument_dict = request['arguments'] 
            self.method.value = request['method'] 
        except Exception as e:
            if self.account.required or \
            self.login.required or \
            self.token.required or \
            self.arguments.required or \
            self.method.required:    
                logging.exception("Error: %s" % e)
                self._code = INVALID_REQUEST


    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        return self._not_null


    def send_request(self):
        if self.method.value == 'online_score':
            online_score_request = OnlineScoreRequest(self.arguments.argument_dict)
            self._not_null = online_score_request.not_null_fileds
            if (online_score_request.code == OK) and online_score_request.is_valid:
                score = online_score_request.get_score()
                return {'score':score}
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        elif self.method.value == 'clients_interests':
            client_intersts_request = ClientsInterestsRequest(self.arguments.argument_dict)
            self._not_null = client_intersts_request.not_null_fileds
            if (client_intersts_request.code == OK) and client_intersts_request.is_valid:
                interests = client_intersts_request.get_interests()
                return interests
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        else:
            error = error[BAD_REQUEST]
            return {'error': error}
    
    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN



def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        account = request.account.value if request.account.is_exist else ''
        digest = hashlib.sha512((request.account.value + request.login.value + SALT).encode('utf-8')).hexdigest()
    if digest == request.token.value:
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
    
    method_request = MethodRequest(request['body'])
    #method_request = MethodRequest({})

    if method_request.code == INVALID_REQUEST:
        return ERRORS[INVALID_REQUEST], method_request.code
    
    if check_auth(method_request) == False:
        return ERRORS[FORBIDDEN], FORBIDDEN

    else:
        #callback method - maybe
        result = method_request.send_request()
        ctx['has'] = method_request.not_null_fileds
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