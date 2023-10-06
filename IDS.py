import mysql.connector as sql
connection = sql.connect(
  host="127.0.0.1",  #"localhost",
  user="root",
  password="",
  database="IDS_System"  #"student"
)
print(connection)


cursor = connection.cursor()
#cursor.execute("CREATE table employeeinfo (id int auto_increment primary key, name varchar(255),department varchar(255))")
"""
query = "insert into employeeinfo (name, department) values (%s, %s)"
value = ("Ram", "IT")
connection.commit()
cursor.execute(query, value)
"""
"""

#to insert multiple records
query = "INSERT INTO employeeinfo (name, department) VALUES (%s, %s)"
values = [("Amit", "RnD"),
        ("Akash", "HR"),
        ("Sumit","ML"),
        ("Kokan","ML"),
        ("Yash","DS"),
        ("Suresh","Accounts")]
connection.commit()
cursor.executemany(query,values)
"""

cursor.execute("Select * from employeeinfo")
print(cursor.fetchall())



#Install mysql connector --> C:\Users\Acer\AppData\Local\Programs\Python\Python37-32\Scripts>pip install mysql-connector-python
#Reference link ->https://medium.com/pythoneers/crud-operation-in-python-with-mysql-databases-e77ee5419c23
