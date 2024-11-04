# SQL Injection Notes

## CheatSheet

### General 	
|Command 	|Description|
|:----|:----|
|mysql -u root -h docker.hackthebox.eu -P 3306 -p 	|login to mysql database|
|SHOW DATABASES| 	List available databases|
|USE users 	|Switch to database|
### Tables 	
|Command 	|Description|
|:----|:----|
|CREATE TABLE logins (id INT, ...) 	|Add a new table|
|SHOW TABLES 	|List available tables in current database|
|DESCRIBE logins 	|Show table properties and columns|
|INSERT INTO table_name VALUES (value_1,..) 	|Add values to table|
|INSERT INTO table_name(column2, ...) VALUES (column2_value, ..) 	|Add values to specific columns in a table|
|UPDATE table_name SET column1=newvalue1, ... WHERE <condition> 	|Update table values|
### Columns 	
|Command 	|Description|
|:----|:----|
|SELECT * FROM table_name |	Show all columns in a table|
|SELECT column1, column2 FROM table_name 	|Show specific columns in a table|
|DROP TABLE logins| 	Delete a table|
|ALTER TABLE logins ADD newColumn INT |	Add new column|
|ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn |	Rename column|
|ALTER TABLE logins MODIFY oldColumn DATE |	Change column datatype|
|ALTER TABLE logins DROP oldColumn 	|Delete column|
### Output 	
|Command 	|Description|
|:----|:----|
|SELECT * FROM logins ORDER BY column_1 |Sort by column|
|SELECT * FROM logins ORDER BY column_1 DESC 	|Sort by column in descending order|
|SELECT * FROM logins ORDER BY column_1 DESC, id ASC |	Sort by two-columns|
|SELECT * FROM logins LIMIT 2 	|Only show first two results|
|SELECT * FROM logins LIMIT 1, 2 	|Only show first two results starting from index 2|
|SELECT * FROM table_name WHERE <condition> 	|List results that meet a condition|
|SELECT * FROM logins WHERE username LIKE 'admin%' |	List results where the name is similar to a given string|

