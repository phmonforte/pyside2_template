"""Implements object oriented modelling for Data Access Layer."""
import os
import hashlib
import sqlite3 as db_api


def date_to_dict(date):
    """Convert sqlite integer to date."""
    year = date // 10 ** 4
    month = date // 10 ** 2 - year * 10 ** 2
    day = date - (date // 10 ** 2) * 10 ** 2
    return (year, month, day)


def store_password(password):
    """Store password and salt."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256',
                              password.encode('utf-8'),
                              salt, 100000)
    return salt+key


def get_password(key):
    """Return tuple salt + password."""
    return (key[:32], key[32:])


def match_password(password, key):
    """Return true if password is the same as the hashed password."""
    salt, hashed = key
    key = hashlib.pbkdf2_hmac('sha256',
                              password.encode('utf-8'),
                              salt, 100000)
    return key == hashed


def date_to_sql(date):
    """Convert data to sqlite integer."""
    return date[0] * 10 ** 4 + date[1] * 10 ** 2 + date[2]


class SQLiteManager:
    """Hold tables and views models.

    Uses the following Table model:
    model = dict {'table_name':[(field1_name, type, mod),(field2_name, type, mod)]}
    Where the Type can be any of the following:
    - date: will be converted to an integer
    - text: will be kept as text
    - bit: will be converted to an integer
    - money: will be converted to an integer
    - real: will be kept as SQLite3 real
    - pwd: will be kept as SQLite3 byte, hashed password, with salt
    """

    def __init__(self, database_file, model=None):
        """Generate database manager to handle tables."""
        self.db_file = database_file
        for name, fields in model.items():
            self.__dict__[name] = Table(name, fields, self)
        self.connection = None
        self.cursor = None

        if not os.path.isfile(database_file):
            self.connect()
            self.create_database()

    def connect(self):
        """Open database connection to db_file."""
        try:
            self.connection = db_api.connect(self.db_file)
            self.cursor = self.connection.cursor()
        except Exception as e:
            print(e)

    def create_database(self):
        """Populate database with tables defined by the Table Model."""
        for _, component in self.__dict__.items():
            if isinstance(component, Table):
                component.create()


class Table:
    """Base class for table models."""

    sql_type = {
        "bit": "integer",
        "int": "integer",
        "real": "real",
        "text": "text",
        "date": "integer",
        "money": "integer",
        "pwd": "blob"
    }

    data_conversor = {
        "bit": (lambda x: 1 if x else 0, bool),
        "int": (int, int),
        "real": (float, float),
        "text": (lambda x: x, lambda x: x),
        "date": (date_to_sql, date_to_dict),
        "money": (lambda x: int(x*100), lambda x: x/100),
        "pwd": (store_password, get_password)
    }

    def __init__(self, table, fields, manager):
        """Create a table."""
        self.table = table
        self.fields = fields
        self.manager = manager

    def list_fields(self):
        return tuple(name for name, _, _ in self.fields)

    def add(self, data):
        """Insert data into table."""

        data_fields = (
            (name, self.data_conversor[d_type][0](data[name]))
            for name, d_type, _ in self.fields
            if name in data
        )
        data_fields = tuple(zip(*data_fields))  # Transpose
        command = "INSERT into %s (" % self.table
        command += ", ".join(data_fields[0])
        command += ") VALUES ("
        command += "? ," * (len(data_fields[0]) - 1) + "?"
        command += ");"

        output = None
        try:
            self.manager.connect()
            self.manager.cursor.execute(command, data_fields[1])
            output = self.manager.cursor.lastrowid
            self.manager.connection.commit()
        except Exception as e:
            print(command)
            print(data_fields[1])
            print(e)
        finally:
            self.manager.connection.close()
        return output

    def update(self, data, condition):
        """Update table data in row identified by condition.

        data = dict {field1: value1, field2: value2}
        condition = tuple ("field1 = ? and field2 LIKE ?",[val1, val2])
        """
        data_fields = (
            (name, self.data_conversor[d_type][0](data[name]))
            for name, d_type, _ in self.fields
            if name in data
        )
        data_fields = tuple(zip(*data_fields))  # Transpose
        command = "UPDATE %s SET " % self.table
        command += ", ".join((n + " = ?" for n in data_fields[0]))
        command += "WHERE %s;" % condition[0]

        try:
            self.manager.connect()
            complete_query_inputs = list(data_fields[1]) + condition[1]
            self.manager.cursor.execute(command, complete_query_inputs)
            self.manager.connection.commit()
        except Exception as e:
            print(command)
            print(e)
        finally:
            self.manager.connection.close()

    def get(self, data, condition):
        """Get data that complies to condition.

        data = dict {field1: value1, field2: value2}
        condition = tuple ("field1 = ? and field2 LIKE ?",[val1, val2])
        """
        data_fields = (
            (name, self.data_conversor[d_type][1])
            for name, d_type, _ in self.fields
            if name in data
        )
        data_fields = tuple(zip(*data_fields))  # Transpose
        command = "SELECT "
        command += ", ".join((n for n in data_fields[0]))
        command += " FROM %s " % self.table
        command += "WHERE %s;" % condition[0]
        output = None
        try:
            self.manager.connect()
            complete_query_inputs = condition[1]
            self.manager.cursor.execute(command, complete_query_inputs)
            output = self.manager.cursor.fetchall()
            self.manager.connection.commit()
        except Exception as e:
            print(command)
            print(e)
        finally:
            self.manager.connection.close()

        if output is None:
            return None
        output = [
            {
                name: cv(col)
                for col, cv, name in zip(item, data_fields[1], data_fields[0])
            }
            for item in output
        ]
        return output

    def create(self):
        """Create table following self.fields guidelines."""
        try:
            self.manager.connect()
            command = "CREATE TABLE %s (" % self.table
            command += ", ".join(
                ["%s %s %s" % (name, self.sql_type[d_type], mod)
                    for name, d_type, mod in self.fields]
            )
            command += ");"
            self.manager.cursor.execute(command)
            self.manager.connection.commit()
        except Exception as e:
            print(command)
            print(e)
        finally:
            self.manager.connection.close()
