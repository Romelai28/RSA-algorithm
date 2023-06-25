import random
import sympy

# clave publica (n,d)
# clabe privada (n,e)


def algoritmo_de_euclides_mcd(n: int, m: int) -> int:
    """Requiere: n, m enteros no ambos nulos."""
    if n == 0 and m == 0:
        raise Exception("No pueden ser ambos nulos")
    if n == 0 or m == 0:
        return max(abs(n), abs(m))
    if abs(n) > abs(m):
        return algoritmo_de_euclides_mcd(n % m, m)
    else:
        return algoritmo_de_euclides_mcd(n, m % n)


def algoritmo_de_euclides_extendido(a: int, b: int) -> (int, int, int):
    """Escribe el mcd como combinación entera de a y b.
    Requiere: a, b no ambos nulos. devuelve d = (a:b) = s*a + t*b"""
    if a == 0 and b == 0:
        raise Exception("No pueden ser ambos nulos")
    r_1: int = a
    r_2: int = b
    s_1: int = 1
    t_1: int = 0
    s_2: int = 0
    t_2: int = 1
    while r_2 != 0:
        k = r_1 // r_2
        r = r_1 % r_2
        s = s_1 - k * s_2
        t = t_1 - k * t_2
        r_1 = r_2
        r_2 = r
        s_1 = s_2
        t_1 = t_2
        s_2 = s
        t_2 = t
    if b < 0:  # Soluciona error con los números negativos.
        s_1 *= (-1)
        t_1 *= (-1)
    return abs(r_1), s_1, t_1


def generador_e(p: int, q: int) -> int:
    """Requiere p, q primos distintos. Devuelve e 1<=e<=(p-1)*(q-1). e es corpimo con (p-1)*(q-1)"""
    if p == q:
        raise Exception("p y q deben ser primos distintos.")
    phi_n: int = (p - 1) * (q - 1)
    while True:
        # "El algoritmo es más eficiente si hago elecciones de e pequeño"
        # e: int = random.randint(1, phi_n)
        e: int = random.randint(1, min((p - 1), (q - 1)))  # Limito las elecciones de e para que no tome valores altos.
        if algoritmo_de_euclides_mcd(e, phi_n) == 1:
            return e


def generador_d(p: int, q: int, e: int) -> int:
    """Requiere p, q primos distintos y e coprimo con (p-1)*(q-1). Devuelve d 1<=d<=(p-1)*(q-1)."""
    # d*e = 1 mod ((p-1)*(q-1))
    # d*e + k*(-m) = 1 donde m = ((p-1)*(q-1))
    # d*e + k*(-((p-1)*(q-1))) = 1
    if p == q:
        raise Exception("p y q deben ser primos distintos.")
    phi_n: int = (p - 1) * (q - 1)
    res_eqn_diofantica: (int, int, int) = algoritmo_de_euclides_extendido(e, -phi_n)
    d: int = res_eqn_diofantica[1]
    assert res_eqn_diofantica[0] == 1  # e debe ser coprimo con (p-1)*(q-1)
    if d < 0:  # Aseguro que 1<=d<=(p-1)*(q-1) y d positivo
        d += (p - 1) * (q - 1)
    return d


def generador_claves(p: int, q: int) -> (int, int):
    """Requiere p, q primos distintos."""
    if p == q:
        raise Exception("p y q deben ser primos distintos.")
    e: int = generador_e(p, q)
    d: int = generador_d(p, q, e)
    return e, d


def generador_tupla_primos(min_primo: int = 7, max_primo: int = 1091) -> (int, int):
    """Genera una tupla de dos primos distintos entre min_primo y max_primo"""
    # sympy.randprime(a,b) -> Return a random prime number in the range [a, b).
    while True:
        p_primo: int = sympy.randprime(min_primo, max_primo + 1)
        q_primo: int = sympy.randprime(min_primo, max_primo + 1)
        if not p_primo == q_primo:
            return p_primo, q_primo


def transformar(a: int, clave: int, p: int, q: int) -> int:
    """Mecanismo del sistema RSA. Requiere p, q primos distintos y 0 <= a < n"""
    if p == q:
        raise Exception("p y q deben ser primos distintos.")
    n: int = p * q
    assert 0 <= a < n
    return (a ** clave) % n


def encriptar_y_desencriptar(a: int, p: int, q: int) -> dict:
    """Requiere 0 <= a < n, p, q primos distintos."""
    if p == q:
        raise Exception("p y q deben ser primos distintos.")
    n: int = p * q
    assert 0 <= a < n
    claves: (int, int) = generador_claves(p, q)
    e: int = claves[0]
    d: int = claves[1]
    encriptado: int = (a ** d) % n
    mensaje_desencriptado: int = (encriptado ** e) % n
    estado: bool = a == mensaje_desencriptado
    return {
        "mensaje": a,
        "primos": [p, q],
        "producto primos (n)": n,
        "claves": {"e": e,
                   "d": d},
        "encriptado": encriptado,
        "mensaje devuelto": mensaje_desencriptado,
        "estado de prueba": estado
    }


def general(a: int) -> dict:
    """Requiere a no negativo, se recomienda a pequeño (menor a p*q)
    Dado un mensaje a, genera un diccionario sobre su encriptación, desencriptación, sus claves y sus números primos"""
    assert a >= 0
    par_primos: (int, int) = generador_tupla_primos()
    while not a < par_primos[0] * par_primos[1]:
        par_primos = generador_tupla_primos()
    return encriptar_y_desencriptar(a, par_primos[0], par_primos[1])


def breaking_rsa_debil(mensaje_encriptado: int, p: int, q: int, d: int) -> int:
    """Clave pública pero sabiendo cuales son p, q primos."""
    # x^d = mensaje_encriptado (mod p * q)
    # e*d = 1 (mod (p-1) * (q-1))
    # x^(e*d) = x (mod p * q)
    # mensaje_encriptado^e = mensaje desencriptado (mod p * q)
    n: int = p*q
    phi_n: int = (p-1)*(q-1)
    e: int = algoritmo_de_euclides_extendido(d, phi_n)[1] % phi_n
    mensaje_encriptado = mensaje_encriptado % n  # Optimiza el calculo de desencriptado.
    assert (e * d) % phi_n == 1  # e*d = 1 (mod (p-1)*(q-1))  # Válida el e calculado
    mensaje_desencriptado: int = (mensaje_encriptado ** e) % n
    assert (mensaje_desencriptado ** d) % n == mensaje_encriptado  # Válida el mensaje desencriptado usando la clave pública.
    return mensaje_desencriptado


def breaking_rsa(mensaje: int, n: int, d: int) -> int:
    """Requiere que n sea de la forma n = p * q con p, q dos primos (el 1 no es primo).
    Inputs: mensaje y la clave pública"""
    primos: list[int] = sympy.primefactors(n)
    p: int = primos[0]
    if len(primos) == 1 and n == p ** 2:
        primos.append(p)
    assert len(primos) == 2  # Agregar el caso p=q para la factorizacion de sympy
    q: int = primos[1]
    assert n == p * q
    return breaking_rsa_debil(mensaje, p, q, d)


# Testing de breaking_rsa:
def testing(numero_intentos: int = 10, tamano_max_mensaje: int = 1000):
    contador_bien: int = 0
    contador_mal: int = 0
    for i in range(numero_intentos):
        test_unit: dict = general(random.randint(1, tamano_max_mensaje))
        romper: int = breaking_rsa(mensaje=test_unit["encriptado"],
                                   n=test_unit["primos"][0] * test_unit["primos"][1],
                                   d=test_unit["claves"]["d"])
        print(test_unit)
        print(f"Obtenido: {romper}")
        print(f"Esperado: {test_unit['mensaje']}")
        estado: bool = romper == test_unit["mensaje"]
        print(f"Estado: {estado}")
        if estado:
            contador_bien += 1
        else:
            contador_mal += 1
    print(f"Contador aciertos: {contador_bien}")
    print(f"Contador fallos: {contador_mal}")
