import hashlib
import datetime
import functools
import unittest

from api import BaseField, PhoneField, EmailField, DateField, GenderField, ClientIDsField, BirthDayField

def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                f(*new_args)
        return wrapper
    return decorator

DEFAULT_TEST_FIELD_VALUE = ''

class TestField(unittest.TestCase):
    required_field = BaseField(required=True, nullable=True)
    non_required_field = BaseField(required=False, nullable=False)

    def test_valid_values(self, value=DEFAULT_TEST_FIELD_VALUE):
        if value != DEFAULT_TEST_FIELD_VALUE:
            self.required_field.validate_value(value)
            self.non_required_field.validate_value(value)

    def test_invalid_values(self, value=DEFAULT_TEST_FIELD_VALUE):
        if value != DEFAULT_TEST_FIELD_VALUE:
            with self.assertRaises(TypeError):
                self.required_field.validate_value(value)
                self.non_required_field.validate_value(value)

    @cases([None])
    def test_field_requirements(self, value):
        with self.assertRaises(TypeError):
            self.required_field.required_field_validation(value)
        self.non_required_field.required_field_validation(value)
        

class TestPhoneField(TestField):
    required_field = PhoneField(required=True, nullable=True)
    non_required_field = PhoneField(required=False, nullable=True)

    @cases([
        '79175002040', '79175002060', 79175002040
    ])
    def test_valid_values(self, phone_value):
        super().test_valid_values(phone_value)

    @cases([
        '89164104549', '+79175002040', '09164104549', '717500204',
        100, 'lorem ipsum'
    ])
    def test_invalid_field(self, phone_value):
        super().test_invalid_values(phone_value)

    
class TestEmailFiled(TestField):
    required_field = EmailField(required=True, nullable=True)
    non_required_field = EmailField(required=False, nullable=True)

    # valid cases
    @cases([
        'stupnikov@otus.ru', 'stupnikov@otus.com', 'くま@otus.ru', '緑@otus.ru',
        'Вышеупомянутый@otus.ru'
    ])
    def test_valid_values(self, email_value):
        super().test_valid_values(email_value)

    # invalid cases 
    @cases([
        100, 200, 'stupnikov', 'stupnikovotus'
    ])
    def test_invalid_values(self, email_value):
        super().test_invalid_values(email_value)


class TestGenderFieldFiled(TestField):
    required_field = GenderField(required=True, nullable=True)
    non_required_field = GenderField(required=False, nullable=True)

    # valid cases
    @cases([
        0,1,2
    ])
    def test_valid_values(self, gender_value):
        super().test_valid_values(gender_value)

    # invalid cases 
    @cases([
        'M', 'F', '3', 5, '1', '01', -1
    ])
    def test_invalid_values(self, gender_value):
        super().test_invalid_values(gender_value)


class TestDateField(TestField):
    required_field = DateField(required=True, nullable=True)
    non_required_field = DateField(required=False, nullable=True)

    # valid cases
    @cases([
        "01.01.1990", "01.01.2000", "01.02.1890"
    ])
    def test_valid_values(self, date_value):
        super().test_valid_values(date_value)

    # invalid cases 
    @cases([
        "01.01.18901", 'XXX'
    ])
    def test_invalid_values(self, date_value):
        super().test_invalid_values(date_value)


class TestBirthdayField(TestField):
    required_field = BirthDayField(required=True, nullable=True)
    non_required_field = BirthDayField(required=False, nullable=True)

    # valid cases
    @cases([
        "01.01.1990", "01.01.2000", 
    ])
    def test_valid_values(self, bdate_value):
        super().test_valid_values(bdate_value)

    # invalid cases 
    @cases([
        "01.01.1890", 'XXX'
    ])
    def test_invalid_values(self, bdate_value):
        super().test_invalid_values(bdate_value)


class TestClientIdsField(TestField):
    required_field = ClientIDsField(required=True, nullable=True)
    non_required_field = ClientIDsField(required=False, nullable=True)

    @cases([
        [1, 2, 3], [1,2], [0]
    ])
    def test_valid_values(self, clients_id_values):
        super().test_valid_values(clients_id_values)

    @cases([
        'client_id', ['0',1,2]
    ])
    def test_invalid_values(self, clients_id_values):
        super().test_invalid_values(clients_id_values)


if __name__ == "__main__":
    unittest.main()
