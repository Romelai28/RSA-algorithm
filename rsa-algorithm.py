import random
import sympy


def algoritmo_de_euclides_mcd(n: int, m: int) -> int:
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
    if b < 0:  # Por alguna razón fixea los números negativos.
        s_1 *= (-1)
        t_1 *= (-1)
    return abs(r_1), s_1, t_1


def generador_e(p: int, q: int) -> int:
    """Requiere p, q primos. Devuelve e 1<=e<=(p-1)*(q-1). e es corpimo con (p-1)*(q-1)"""
    while True:
        # "El algoritmo es más eficiente si hago elecciones de e pequeño"
        # e: int = random.randint(1, (p - 1) * (q - 1))
        e: int = random.randint(1, min((p - 1), (q - 1)))  # Limito las elecciones de e para que no tome valores altos.
        if algoritmo_de_euclides_mcd(e, (p - 1) * (q - 1)) == 1:
            return e


def generador_d(p: int, q: int, e: int) -> int:
    """Requiere p, q primos e coprimo con (p-1)*(q-1). Devuelve d 1<=d<=(p-1)*(q-1)."""
    # d*e = 1 mod ((p-1)*(q-1))
    # d*e + k*(-m) = 1 donde m = ((p-1)*(q-1))
    # d*e + k*(-((p-1)*(q-1))) = 1
    res_eqn_diofantica: (int, int, int) = algoritmo_de_euclides_extendido(e, -(p - 1) * (q - 1))
    d: int = res_eqn_diofantica[1]
    assert res_eqn_diofantica[0] == 1  # e debe ser coprimo con (p-1)*(q-1)
    if d < 0:  # Aseguro que 1<=d<=(p-1)*(q-1) (d positivo)
        d += (p - 1) * (q - 1)
    return d


def generador_claves(p: int, q: int) -> (int, int):
    """Requiere p,q primos"""
    e: int = generador_e(p, q)
    d: int = generador_d(p, q, e)
    return e, d


def generador_tupla_primos(min_primo: int = 7, max_primo: int = 1091) -> (int, int):
    # sympy.randprime(a,b) -> Return a random prime number in the range [a, b).
    p_primo = sympy.randprime(min_primo, max_primo + 1)
    q_primo = sympy.randprime(min_primo, max_primo + 1)
    return p_primo, q_primo


def transformar(a: int, clave: int, p: int, q: int) -> int:
    """Mecanismo del sistema RSA. Requiere p, q primos y 0 <= a < n"""
    n: int = p * q
    assert 0 <= a < n
    return (a ** clave) % n


def encriptar_y_desencriptar(a: int, p: int, q: int):
    """Requiere 0 <= a < n, p, q primos."""
    n = p * q
    assert 0 <= a < n
    # print(f"primos elegidos: {p} y {q}")
    # print(f"n: {n}")
    # print(f"mensaje: {a}")
    claves: (int, int) = generador_claves(p, q)
    e = claves[0]
    d = claves[1]
    # print(f"claves: {claves}")
    encriptado: int = (a ** d) % n
    # print(f"encriptado: {encriptado}")
    mensaje_desencriptado: int = (encriptado ** e) % n
    # print(f"mensaje devuelto: {mensaje_desencriptado}")
    estado = a == mensaje_desencriptado
    # print(f"¿Son iguales? {estado}")
    return {
        "mensaje": a,
        "primos": {"p": p,
                   "q": q},
        "producto primos (n)": n,
        "claves": {"e": e,
                   "d": d},
        "encriptado": encriptado,
        "mensaje devuelto": mensaje_desencriptado,
        "estado de prueba": estado
    }


def general(a: int):
    """Requiere a no negativo, se recomienda a pequeño (menor a p*q)"""
    assert a >= 0
    par_primos = generador_tupla_primos()
    while not a < par_primos[0] * par_primos[1]:
        par_primos = generador_tupla_primos()
    return encriptar_y_desencriptar(a, par_primos[0], par_primos[1])


print(general(100))
