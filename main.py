import getpass
import io
import os
import sys
import time

if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import crypto
import db
import generator

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwords.db")

MAX_LOGIN_ATTEMPTS = 3

PASSWORD_DISPLAY_TIME = 10


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def print_header() -> None:
    print("=" * 56)
    print("         LOCAL PASSWORD MANAGER  ")
    print("=" * 56)


def print_menu() -> None:
    print("\n--- MENU ---")
    print("  [1] Dodaj hasło")
    print("  [2] Pobierz hasło")
    print("  [3] Lista serwisów")
    print("  [4] Generuj hasło")
    print("  [5] Usuń hasło")
    print("  [6] Wyjście")
    print()


def print_services_table(services: list[tuple[str, str, str]]) -> None:
    if not services:
        print("\n  Brak zapisanych haseł.\n")
        return

    max_service = max(len(s[0]) for s in services)
    max_user = max(len(s[1]) for s in services)
    col_s = max(max_service, 8)
    col_u = max(max_user, 5)

    header = f"  {'Serwis':<{col_s}}  {'Login':<{col_u}}  {'Data dodania'}"
    separator = "  " + "-" * (col_s + col_u + 25)

    print(f"\n{header}")
    print(separator)
    for service_name, username, created_at in services:
        date_str = created_at[:19].replace("T", " ")
        print(f"  {service_name:<{col_s}}  {username:<{col_u}}  {date_str}")
    print(separator)
    print(f"  Łączna liczba wpisów: {len(services)}\n")




def setup_master_password(conn) -> bytes:
    print("\n╔══════════════════════════════════════════════════════╗")
    print("║   PIERWSZE URUCHOMIENIE — Utwórz Master Password     ║")
    print("╠══════════════════════════════════════════════════════╣")
    print("║  Master Password chroni wszystkie Twoje hasła.       ║")
    print("║  Zapamiętaj je dobrze — nie da się go odzyskać!      ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    while True:
        master_pw = getpass.getpass("  Utwórz Master Password (min. 8 znaków): ")

        if len(master_pw) < 8:
            print("  ✗ Hasło musi mieć minimum 8 znaków. Spróbuj ponownie.\n")
            continue

        confirm_pw = getpass.getpass("  Potwierdź Master Password: ")

        if master_pw != confirm_pw:
            print("  ✗ Hasła nie są identyczne. Spróbuj ponownie.\n")
            continue

        break

    salt = crypto.generate_salt()
    key = crypto.derive_key(master_pw, salt)
    token = crypto.create_verification_token(key)
    db.save_master_config(conn, salt, token)

    print("\n  ✓ Master Password został utworzony pomyślnie!\n")
    return key


def login(conn) -> bytes | None:
    salt, token = db.get_master_config(conn)

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        master_pw = getpass.getpass(
            f"\n  Podaj Master Password (próba {attempt}/{MAX_LOGIN_ATTEMPTS}): "
        )

        key = crypto.derive_key(master_pw, salt)

        if crypto.verify_master_password(key, token):
            print("  ✓ Zalogowano pomyślnie!\n")
            return key

        remaining = MAX_LOGIN_ATTEMPTS - attempt
        if remaining > 0:
            print(f"  ✗ Niepoprawne hasło. Pozostało prób: {remaining}")
        else:
            print("\n  ✗ Wyczerpano limit prób. Program zostanie zamknięty.")

    return None


def action_add_password(conn, key: bytes) -> None:
    print("\n--- Dodaj hasło ---")
    service = input("  Serwis (np. Facebook): ").strip()
    if not service:
        print("  ✗ Nazwa serwisu nie może być pusta.")
        return

    username = input("  Login/email: ").strip()
    if not username:
        print("  ✗ Login nie może być pusty.")
        return

    print("  Hasło - wpisz ręcznie lub wciśnij klawisz [g] by wygenerować:")
    password_input = getpass.getpass("  Hasło: ")

    if password_input.lower() == "g":
        length_str = input(
            f"  Długość hasła ({generator.MIN_LENGTH}-{generator.MAX_LENGTH}, "
            f"domyślnie {generator.DEFAULT_LENGTH}): "
        ).strip()

        length = generator.DEFAULT_LENGTH
        if length_str:
            try:
                length = int(length_str)
            except ValueError:
                print(
                    f"  ⚠ Nieprawidłowa wartość, użyto domyślnej ({generator.DEFAULT_LENGTH})."
                )

        try:
            password_input = generator.generate_password(length)
            print(f"\n  Wygenerowane hasło: {password_input}\n")
        except ValueError as e:
            print(f"  ✗ {e}")
            return

    if not password_input:
        print("  ✗ Hasło nie może być puste.")
        return

    encrypted = crypto.encrypt_password(key, password_input)

    if db.add_password(conn, service, username, encrypted):
        print(f"\n  ✓ Hasło dla {service} ({username}) zostało zapisane.")
    else:
        overwrite = input(
            f"  ⚠ Wpis dla {service} ({username}) już istnieje. Nadpisać? [t/n]: "
        ).strip().lower()
        if overwrite == "t":
            db.update_password(conn, service, username, encrypted)
            print(f"  ✓ Hasło zaktualizowane.")
        else:
            print("  Anulowano.")


def action_get_password(conn, key: bytes) -> None:
    print("\n--- Pobierz hasło ---")
    query = input("  Nazwa serwisu (lub fragment do wyszukania): ").strip()
    if not query:
        print("  ✗ Podaj nazwę serwisu.")
        return

    results = db.search_services(conn, query)

    if not results:
        print(f"  ✗ Nie znaleziono serwisu pasującego do \"{query}\".")
        return

    if len(results) == 1:
        service, username, _ = results[0]
    else:
        print("\n  Znalezione wpisy:")
        for i, (s, u, _) in enumerate(results, 1):
            print(f"    [{i}] {s} — {u}")

        choice = input("\n  Wybierz numer: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                service, username, _ = results[idx]
            else:
                print("  ✗ Nieprawidłowy numer.")
                return
        except ValueError:
            print("  ✗ Nieprawidłowy wybór.")
            return

    encrypted = db.get_password(conn, service, username)
    if encrypted is None:
        print("  ✗ Nie znaleziono hasła.")
        return

    try:
        decrypted = crypto.decrypt_password(key, encrypted)
    except Exception:
        print("  ✗ Błąd deszyfrowania - dane mogą być uszkodzone.")
        return

    print(f"\n  Serwis:  {service}")
    print(f"  Login:   {username}")
    print(f"  Hasło:   {decrypted}")
    print(
        f"\n   Hasło zostanie wyczyszczone z ekranu za {PASSWORD_DISPLAY_TIME}s..."
    )

    try:
        time.sleep(PASSWORD_DISPLAY_TIME)
    except KeyboardInterrupt:
        pass

    clear_screen()
    print("  ✓ Ekran wyczyszczony.\n")


def action_list_services(conn) -> None:
    print("\n--- Lista serwisów ---")
    services = db.list_services(conn)
    print_services_table(services)


def action_generate_password() -> None:
    print("\n--- Generator haseł ---")
    length_str = input(
        f"  Długość hasła ({generator.MIN_LENGTH}-{generator.MAX_LENGTH}, "
        f"domyślnie {generator.DEFAULT_LENGTH}): "
    ).strip()

    length = generator.DEFAULT_LENGTH
    if length_str:
        try:
            length = int(length_str)
        except ValueError:
            print(
                f"  ⚠ Nieprawidłowa wartość, użyto domyślnej ({generator.DEFAULT_LENGTH})."
            )

    try:
        password = generator.generate_password(length)
        print(f"\n  Wygenerowane hasło ({length} znaków):")
        print(f"  {password}\n")
    except ValueError as e:
        print(f"  ✗ {e}")


def action_delete_password(conn) -> None:
    print("\n--- Usuń hasło ---")
    service = input("  Serwis: ").strip()
    if not service:
        print("  ✗ Podaj nazwę serwisu.")
        return

    results = db.search_services(conn, service)
    if not results:
        print(f"  ✗ Nie znaleziono serwisu \"{service}\".")
        return

    if len(results) == 1:
        service_name, username, _ = results[0]
    else:
        print("\n  Znalezione wpisy:")
        for i, (s, u, _) in enumerate(results, 1):
            print(f"    [{i}] {s} — {u}")

        choice = input("\n  Który wpis usunąć? Podaj numer: ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                service_name, username, _ = results[idx]
            else:
                print("  ✗ Nieprawidłowy numer.")
                return
        except ValueError:
            print("  ✗ Nieprawidłowy wybór.")
            return

    confirm = input(
        f"  Na pewno usunąć {service_name} ({username})? [t/n]: "
    ).strip().lower()

    if confirm == "t":
        if db.delete_password(conn, service_name, username):
            print(f"  ✓ Wpis {service_name} ({username}) został usunięty.")
        else:
            print("  ✗ Nie udało się usunąć wpisu.")
    else:
        print("  Anulowano.")




def main() -> None:
    clear_screen()
    print_header()

    conn = db.init_db(DB_PATH)

    try:
        if not db.is_master_set(conn):
            key = setup_master_password(conn)
        else:
            key = login(conn)
            if key is None:
                conn.close()
                sys.exit(1)

        while True:
            print_menu()
            choice = input("  Wybierz opcję [1-6]: ").strip()

            if choice == "1":
                action_add_password(conn, key)
            elif choice == "2":
                action_get_password(conn, key)
            elif choice == "3":
                action_list_services(conn)
            elif choice == "4":
                action_generate_password()
            elif choice == "5":
                action_delete_password(conn)
            elif choice == "6":
                print("\n  Do zobaczenia! 🔒\n")
                break
            else:
                print("  ✗ Nieprawidłowa opcja. Wybierz 1-6.")

    except KeyboardInterrupt:
        print("\n\n  Przerwano (Ctrl+C). Do zobaczenia! \n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
