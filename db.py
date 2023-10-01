import pymysql

connection = pymysql.connect(
    host='185.27.133.2',
    user='jocappsi_user',
    password='FI3QU7RYGJZA',
    database='jocappsi_JOC'
)

def query(sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        result = cursor.fetchall()
    return result

# Ensure to close the connection when your app exits
def close():
    connection.close()