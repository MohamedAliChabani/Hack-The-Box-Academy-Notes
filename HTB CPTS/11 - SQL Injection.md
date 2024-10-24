# <mark class="hltr-pink">SQL Injection</mark>

## <mark class="hltr-cyan">Types of SQL Injection</mark>

![[Pasted image 20241013193151.png]]

In simple cases, the output of both the intended and the new query may be printed directly on the front end, and we can directly read it. This is known as `In-band` SQL injection, and it has two types: `Union Based` and `Error Based`.

With `Union Based` SQL injection, we may have to specify the exact location, 'i.e., column', which we can read, so the query will direct the output to be printed there. As for `Error Based` SQL injection, it is used when we can get the `PHP` or `SQL` errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query.

In more complicated cases, we may not get the output printed, so we may utilize SQL logic to retrieve the output character by character. This is known as `Blind` SQL injection, and it also has two types: `Boolean Based` and `Time Based`.

With `Boolean Based` SQL injection, we can use SQL conditional statements to control whether the page returns any output at all, 'i.e., original query response,' if our conditional statement returns `true`. As for `Time Based` SQL injections, we use SQL conditional statements that delay the page response if the conditional statement returns `true` using the `Sleep()` function.

Finally, in some cases, we may not have direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there. This is known as `Out-of-band` SQL injection.

In this module, we will only be focusing on introducing SQL injections through learning about `Union Based` SQL injection.

## <mark class="hltr-cyan">Subverting Query Logic</mark>

Before we start subverting the web application's logic and attempting to bypass the authentication, we first have to test whether the login form is vulnerable to SQL injection. To do that, we will try to add one of the below payloads after our username and see if it causes any errors or changes how the page behaves:

![[Pasted image 20241013194038.png]]

```sql
admin' or '1'='1
```

![[Pasted image 20241013195052.png]]

## <mark class="hltr-cyan">Using Comments</mark>

❗: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end.

Example 1:
```sql
SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';
```

![[Pasted image 20241013200102.png]]

Example 2:
```sql
tom')-- 
```

![[Pasted image 20241013200545.png]]

## <mark class="hltr-cyan">Union Clause</mark>
### <mark class="hltr-orange">Union</mark>
The [Union](https://dev.mysql.com/doc/refman/8.0/en/union.html) clause is used to combine results from multiple `SELECT` statements. This means that through a `UNION` injection, we will be able to `SELECT` and dump data from all across the DBMS, from multiple tables and databases. Let us try using the `UNION` operator in a sample database. First, let us see the content of the `ports` table:

```shell-session
mysql> SELECT * FROM ports;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

Next, let us see the output of the `ships` tables:

```shell-session
mysql> SELECT * FROM ships;

+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
```

Now, let us try to use `UNION` to combine both results:
```shell-session
mysql> SELECT * FROM ports UNION SELECT * FROM ships;

+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

### <mark class="hltr-orange">Even Columns</mark>

A `UNION` statement can only operate on `SELECT` statements with an equal number of columns. For example, if we attempt to `UNION` two queries that have results with a different number of columns, we get the following error:

```shell-session
mysql> SELECT city FROM ports UNION SELECT * FROM ships;

ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

### <mark class="hltr-orange">Un-even Columns</mark>

We will find out that the original query will usually not have the same number of columns as the SQL query we want to execute, so we will have to work around that. For example, suppose we only had one column. In that case, we want to `SELECT`, we can put <mark class="hltr-red">junk data</mark> for the remaining required columns so that the total number of columns we are `UNION`ing with remains the same as the original query.

For example, we can use any string as our junk data, and the query will return the string as its output for that column. If we `UNION` with the string `"junk"`, the `SELECT` query would be `SELECT "junk" from passwords`, which will always return `junk`. We can also use numbers. For example, the query `SELECT 1 from passwords` will always return `1` as the output.

❗: For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.

Example:
- employees table has 6 columns
- departments table has 2 columns

```sql
select * from employees union select dept_no, dept_name, NULL, NULL, NULL, NULL from departments;
```

## <mark class="hltr-cyan">Union Injection</mark>

![[Pasted image 20241014114806.png]]

Since we caused an error, this may mean that the page is vulnerable to SQL injection. This scenario is ideal for exploitation through Union-based injection, <mark class="hltr-green">as we can see our queries' results</mark>.

### <mark class="hltr-orange">Detect number of columns</mark>

Before going ahead and exploiting Union-based queries, we need to find the number of columns selected by the server. There are two methods of detecting the number of columns:

- Using `ORDER BY`
- Using `UNION`

#### <mark class="hltr-grey">Using ORDER BY</mark>

For example, we can start with `order by 1`, sort by the first column, and succeed, as the table must have at least one column. Then we will do `order by 2` and then `order by 3` until we reach a number that returns an error, or the page does not show any output, which means that this column number does not exist. The final successful column we successfully sorted by gives us the total number of columns.

```sql
' order by 1-- -
```
As we see, we get a normal result:
![[Pasted image 20241014115102.png]]


Until we reach 5:
```sql
' order by 5-- -
```
![[Pasted image 20241014115137.png]]

This means that this table has exactly 4 columns .

#### <mark class="hltr-grey">Using UNION</mark>

The other method is to attempt a Union injection with a different number of columns <mark class="hltr-green">until we successfully get the results back</mark>.

❗: The first method (order by) always returns the results until we hit an error, while this method always gives an error until we get a success.

We can start by injecting a 3 column `UNION` query:
```sql
cn' UNION select 1,2,3-- -
```

We get an error saying that the number of columns don’t match.

So, let’s try four columns and see the response:
```sql
cn' UNION select 1,2,3,4-- -
```

This time we successfully get the results, meaning once again that the table has 4 columns. We can use either method to determine the number of columns.

Once we know the number of columns, we know how to form our payload, and we can proceed to the next step.

### <mark class="hltr-orange">Location of Injection</mark>

While a query may return multiple columns, the web application may only display some of them. So, if we inject our query in a column that is not printed on the page, we will not get its output. This is why we need to determine which columns are printed to the page, to determine where to place our injection. In the previous example, while the injected query returned 1, 2, 3, and 4, we saw only 2, 3, and 4 displayed back to us on the page as the output data:

![[Pasted image 20241014180906.png]]

It is very common that not every column will be displayed back to the user. For example, the ID field is often used to link different tables together, but the user doesn't need to see it. This tells us that columns 2 and 3, and 4 are printed to place our injection in any of them. `We cannot place our injection at the beginning, or its output will not be printed.`

This is the benefit of using numbers as our junk data, as it makes it easy to track which columns are printed, so we know at which column to place our query. To test that we can get actual data from the database 'rather than just numbers,' we can use the `@@version` SQL query as a test and place it in the second column instead of the number 2:

```sql
cn' UNION select 1,@@version,3,4-- -
```

![[Pasted image 20241014181024.png]]

---

# <mark class="hltr-pink">Exploitation</mark>

## <mark class="hltr-cyan">Database Enumeration</mark>

### <mark class="hltr-orange">MySQL Fingerprinting</mark>

Before enumerating the database, we usually need to identify the type of DBMS we are dealing with. This is because each DBMS has different queries, and knowing what it is will help us know what queries to use.

As an initial guess, if the webserver we see in HTTP responses is `Apache` or `Nginx`, it is a good guess that the webserver is running on Linux, so the DBMS is likely `MySQL`. The same also applies to Microsoft DBMS if the webserver is `IIS`, so it is likely to be `MSSQL`. However, this is a far-fetched guess, as many other databases can be used on either operating system or web server. So, there are different queries we can test to fingerprint the type of database we are dealing with.

The following queries and their output will tell us that we are dealing with `MySQL`:

![[Pasted image 20241016125104.png]]

### <mark class="hltr-orange">Information Schema Database</mark>

The [INFORMATION_SCHEMA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-introduction.html) database contains metadata about the databases and tables present on the server. This database plays a crucial role while exploiting SQL injection vulnerabilities.

### <mark class="hltr-orange">SCHEMATA</mark>

To start our enumeration, we should find what databases are available on the DBMS. The table [SCHEMATA](https://dev.mysql.com/doc/refman/8.0/en/information-schema-schemata-table.html) in the `INFORMATION_SCHEMA` database contains information about all databases on the server. It is used to obtain database names so we can then query them. The `SCHEMA_NAME` column contains all the database names currently present.

```shell-session
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

Let us find out which database the web application is running to retrieve data. We can find the <mark class="hltr-green">current database</mark> with the `SELECT database()` query.

```sql
cn' UNION select 1,database(),2,3-- -
```


### <mark class="hltr-orange">Tables</mark>

We need to get a list of the tables to query them with a `SELECT` statement. To find all tables within a database, we can use the `TABLES` table in the `INFORMATION_SCHEMA` Database.

In this example we will list all the names of the tables that reside in the 'dev' database: 
```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
```

### <mark class="hltr-orange">Colums</mark>

To dump the data of the `credentials` table, we first need to find the column names in the table, which can be found in the `COLUMNS` table in the `INFORMATION_SCHEMA` database

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
```

### <mark class="hltr-orange">Data</mark>

Now that we have all the information, we can form our `UNION` query to dump data of the `username` and `password` columns from the `credentials` table in the `dev` database. We can place `username` and `password` in place of columns 2 and 3:

```sql
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

