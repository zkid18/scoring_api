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


class BaseField(object):
    '''
    BaseFiled class - interface class for Field object
    '''
    def __init__(self, required, nullable, name):
        '''
        The __init__ method takes the following parameters:
        1. reuqired - Boolean value indicated that value is required
        2. nullable - Boolena value indicated that value can be nullable
        3. name - String value for field name
        '''

        self.required = required
        self.nullable = nullable
        self.name = str(name)
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
        3. Check field for correct format
        '''
        if ((not self.nullable) and (self.value == '')):
            logging.exception("{} nullable".format(self.name))
            return False
  
        elif (self.required) and (self.value == None):
            logging.exception("{} is nullable".format(self.name))
            return False

        elif self._is_wrong_type:
            return False

        return True


class CharField(BaseField):
    '''
    Char filed class - BaseField implemenation for Char fields
    '''

    def __init__(self, required, nullable, name):
        super().__init__(required, nullable, name)

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
        if (isinstance(value, str)):
            self._value = value
        else:
            self._is_wrong_type = True
            logging.exception("{} is wrong type".format(self.name))
            raise KeyError('Wrong type of {}'.format(self.name))


class ArgumentsField(object):
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
        self._value = None
        self.required = required
        self.nullable = nullable
        self.name = 'arguments'

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class EmailField(CharField):
    '''
    Email Filed class - CharFiled class implemenation for email field
    '''
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
        '''
        Validation condition - check of @ exists in the email value
        '''
        if '@' not in value:
            self._is_wrong_type = True
            logging.exception("Email {} is not valid".format(self.name))
            raise KeyError('Wrong type of {}'.format(self.name))
        else:
            self._value = value
            # TO-DO research the following construction
            # super(EmailField, EmailField).value.__set__(self, value)


class PhoneField(BaseField):
    '''
    PhoneField class - BaseField implemenation for phone field
    '''
    def __init__(self, required, nullable):
        name = 'phone'
        super().__init__(required, nullable, name)

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
        '''
        Validation conditions:
        1. Length value = 11
        2. String value starts from 7
        '''
        if (len(str(value)) == 11) and (str(value)[0]) == '7':
            self._value = value
        else:
            self._is_wrong_type = True
            logging.exception("Phone {} is not valid".format(value))
            raise KeyError('Wrong type of {}'.format(self.name))
            # TO-DO research the following construction
            # super(PhoneField, PhoneField).value.__set__(self, value)


class DateField(BaseField):
    '''
    DateField class - BaseField implemenation for dates field
    '''
    def __init__(self, required, nullable):
        name = 'date'
        super().__init__(required, nullable, name)

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
        '''
        Validation conditions:
        1. Date format: DD.MM.YYYY
        '''
        lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")
        date = re.search(lineformat,value)
        if date:
            self._value = value
        else:
            self._is_wrong_type = True
            logging.exception("Invalid date is provided")
            raise KeyError('Wrong type of {}'.format(self.name))


class BirthDayField(BaseField):
    '''
    BirthDayField class - BaseField implemenation for birthday field
    '''
    def __init__(self, required, nullable):
        name = 'birthday'
        super().__init__(required, nullable, name)

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
        '''
        Validation for condition:
        1. Date format: DD.MM.YYYY
        2. No more than 70 years have passed from the Date
        '''
        lineformat = re.compile(r"""^(?P<day>([0-2][0-9]|(3)[0-1]))(\.|\/)(?P<month>(((0)[0-9])|((1)[0-2])))(\.|\/)(?P<year>\d{4})$""")
        birthday = re.search(lineformat, value)
        if birthday:
            birthday_dict = birthday.groupdict()

            if (2020-int(birthday_dict['year']) < 70) or (len(birthday_dict) == 0):
                self._is_wrong_type = True
                logging.exception("Invalid birthday is provided")
                raise KeyError('Wrong type of {}'.format(self.name))
     
            else:
                self._value = birthday


class GenderField(BaseField):
    '''
    GenderField class - BaseField implemenation for birthday field
    '''
    def __init__(self, required, nullable):
        name = 'gender'
        super().__init__(required, nullable, name)

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
        '''
        Validation for condition:
        1. Integer in the range (0,1,2)
        '''
        if (int(value) not in [0,1,2]):
            self._is_wrong_type = True
            logging.exception("Invalid gender {} provided")
            KeyError('Wrong type of {}'.format(self.name))
        else:
            self._value = value


class ClientIDsField(BaseField):
    '''
    GenderField class - BaseField implemenation for clientsID field
    '''
    def __init__(self, required, nullable):
        name = 'client_ids'
        super().__init__(required, nullable, name)

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
    def value(self, value_list):
        '''
        clients_id - list of the fields
        '''
        if isinstance(value_list, list) and (len(value_list) > 0) and \
            (all(isinstance(x, int) for x in value_list)):
            self._value = value_list
        else:
            raise KeyError('Wrong type of {}'.format(self.name))
            self._is_wrong_type = True
            logging.exception("For ClientID list is required")


class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)
    _code = OK

    def __init__(self, arguments):
        self._try_init_argument(self.client_ids, arguments)
        self._try_init_argument(self.date, arguments)

    def _try_init_argument(self, field, arguments):
        try:
            field.value = arguments[field.name]
        except KeyError as e:
            if field.required:
                logging.exception("Error {}".format(e))
                self._code = INVALID_REQUEST

    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        fileds = [x.name for x in filter(lambda x: x.is_exist==True,[self.client_ids, self.date])]
        return fileds

    @property
    def is_valid(self):
        return True if self.date.is_valid and self.client_ids.is_valid \
                else False

    @property 
    def num_clinets(self):
        return len(self.client_ids.value)

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

        self._try_init_argument(self.first_name, arguments)
        self._try_init_argument(self.last_name, arguments)
        self._try_init_argument(self.email, arguments)
        self._try_init_argument(self.phone, arguments)
        self._try_init_argument(self.birthday, arguments)
        self._try_init_argument(self.gender, arguments)

    def _try_init_argument(self, field, arguments):
        try:
            field.value = arguments[field.name]
        except KeyError as e:
            if field.required:
                logging.exception("Error {}".format(e))
                self._code = INVALID_REQUEST

    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        fileds = [x.name for x in filter(lambda x: x.is_exist==True,[self.first_name, self.last_name, self.phone, self.email, self.birthday, self.gender])]
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
                logging.exception('Not valid')
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

    account = CharField(required=False, nullable=True, name='account')
    login = CharField(required=True, nullable=True, name='login')
    token = CharField(required=True, nullable=True, name='token')
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False, name='method')
    _code = OK
    _not_null = None

    def __init__(self, request):
        self._try_init_argument(self.account, request)
        self._try_init_argument(self.token, request)
        self._try_init_argument(self.login, request)
        self._try_init_argument(self.arguments, request)
        self._try_init_argument(self.method, request)

    def _try_init_argument(self, field, request):
        try:
            field.value = request[field.name]
        except KeyError as e:
            if field.required:
                logging.exception("Error {}".format(e))
                self._code = INVALID_REQUEST

    @property
    def code(self):
        return self._code

    @property
    def not_null_fileds(self):
        return self._not_null

    def send_request(self, ctx):
        if self.method.value == 'online_score':
            online_score_request = OnlineScoreRequest(self.arguments.value)
            self._not_null = online_score_request.not_null_fileds
            ctx['has'] = online_score_request.not_null_fileds
            if self.is_admin:
                return {'score': 42}
            elif (online_score_request.code == OK) and online_score_request.is_valid:
                score = online_score_request.get_score()
                return {'score':score}
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        elif self.method.value == 'clients_interests':
            client_intersts_request = ClientsInterestsRequest(self.arguments.value)
            self._not_null = client_intersts_request.not_null_fileds
            ctx['has'] = client_intersts_request.not_null_fileds
            if (client_intersts_request.code == OK) and client_intersts_request.is_valid:
                interests = client_intersts_request.get_interests()
                ctx['nclients'] = client_intersts_request.num_clinets
                return interests
            else:
                error = ERRORS[INVALID_REQUEST]
                return {'error': error}
        else:
            error = error[BAD_REQUEST]
            return {'error': error}
 
    @property
    def is_admin(self):
        return self.login.value == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        account = request.account.value if request.account.is_exist else ''
        digest = hashlib.sha512((account + request.login.value + SALT).encode('utf-8')).hexdigest()
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

    if method_request.code == INVALID_REQUEST:
        return ERRORS[INVALID_REQUEST], method_request.code

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
