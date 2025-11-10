Stack memory (o memoria de pila) es una región de la memoria del proceso que se utiliza para almacenar datos temporales asociados con la ejecución de funciones. Es el espacio donde se guardan variables locales, parámetros de funciones y direcciones de retorno durante la ejecución de un programa.

- Organización LIFO (Last In, First Out): El último dato en entrar es el primero en salir. Cada vez que se llama a una función, se crea un nuevo stack frame encima del anterior.

- Gestión automática: El sistema gestiona la pila de forma automática: se reserva memoria al entrar en una función y se libera al salir de ella.

- Almacenamiento temporal: Ideal para datos que solo son necesarios mientras una función está activa.

- Tamaño limitado: La pila tiene un tamaño fijo (por ejemplo, unos pocos MB). Si se excede (por demasiadas llamadas recursivas o grandes variables locales), ocurre un stack overflow.



| Acción               | Qué pasa en la pila                               |
| -------------------- | ------------------------------------------------- |
| Llamas a una función | Se crea un nuevo *stack frame*                    |
| Termina la función   | Se destruye automáticamente su *stack frame*      |
| Variables locales    | Viven solo mientras la función está activa        |
| Orden de ejecución   | LIFO (el último en entrar es el primero en salir) |


