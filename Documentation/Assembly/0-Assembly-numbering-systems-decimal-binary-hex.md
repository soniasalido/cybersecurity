

![Sistemas numéricos](capturas/numeric-systems.png)


![Sistemas numéricos](capturas/numeric-systems-2.png)

![Sistemas numéricos](capturas/numeric-systems-3.png)

Circuito integrado central:
![Gates](capturas/gates.png)

Vemos un chip representado con varias puertas lógicas internas. Contiene múltiples puertas lógicas del mismo tipo (en este caso parecen AND u OR en pares).

Cada “bloque” en el chip es una puerta lógica independiente, con sus entradas y salida.

## Microprocesador
![microprocesador](capturas/microprocesador.png)

### 1. Control Unit (Unidad de Control)
- Es el "cerebro organizador" de la CPU.
- Funciones:
  - Lee e interpreta las instrucciones del programa.
  - Genera las señales necesarias para coordinar el resto de los componentes.
  - Decide qué operaciones debe realizar la ALU y cuándo mover datos a/desde los registros.

### 2. ALU (Arithmetic Logic Unit – Unidad Aritmética Lógica)
- Es el componente que realiza operaciones matemáticas y lógicas.
- Operaciones típicas:
  - Aritméticas: suma, resta, multiplicación, división.
  - Lógicas: AND, OR, XOR, NOT, comparaciones.
  - Recibe instrucciones y datos desde la Unidad de Control y los registros internos.

### 3. Internal Registers (Registros Internos)
- Pequeñas memorias ultrarrápidas dentro del procesador.
-  Funciones:
  - Almacenan temporalmente datos y resultados intermedios.
  - Guardan direcciones de memoria y contadores de programa.
  - Permiten a la CPU trabajar sin depender continuamente de la memoria RAM (que es más lenta).

### Flujo básico según el diagrama
- La Unidad de Control lee una instrucción y decide qué hacer.
- Envía la orden a la ALU para que realice la operación.
- El resultado se guarda en los registros internos.
- Desde los registros, los datos pueden enviarse a la memoria, a dispositivos externos o usarse en la siguiente instrucción.


## Funcionamiento del procesador
![Funcionamiento Procesador](capturas/funionamiento-procesador.png)



![Funcionamiento Procesador-2](capturas/funcionamiento-procesador-1.png)

![Funcionamiento Procesador-2](capturas/funcionamiento-procesador-3.png)
