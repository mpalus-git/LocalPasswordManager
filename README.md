# 🔐 Local Password Manager

Lokalny menedżer haseł działający w terminalu. Przechowuje hasła w zaszyfrowanej bazie danych SQLite, zabezpieczonej jednym hasłem głównym (Master Password).

---

## Spis treści

- [Funkcje](#funkcje)
- [Bezpieczeństwo](#bezpieczeństwo)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Uruchomienie](#uruchomienie)
- [Użytkowanie](#użytkowanie)
- [Struktura projektu](#struktura-projektu)

---

## Funkcje

| Funkcja | Opis |
|---|---|
| **Master Password** | Jedno hasło główne chroni wszystkie pozostałe |
| **Szyfrowanie AES-128** | Hasła szyfrowane algorytmem Fernet (AES-CBC + HMAC) |
| **Generator haseł** | Kryptograficznie bezpieczny generator (8–128 znaków) |
| **Wyszukiwanie** | Szybkie wyszukiwanie haseł po fragmencie nazwy serwisu |
| **Auto-czyszczenie** | Odszyfrowane hasło znika z ekranu po 10 sekundach |
| **Limit prób logowania** | Maksymalnie 3 próby podania Master Password |
| **Pełny CRUD** | Dodawanie, odczyt, aktualizacja i usuwanie wpisów |

---

## Bezpieczeństwo

- **Derywacja klucza:** PBKDF2-HMAC-SHA256 z 600 000 iteracjami i 16-bajtowym losowym salt
- **Szyfrowanie:** Fernet (AES-128-CBC + HMAC-SHA256) z biblioteki `cryptography`
- **Generator:** Wykorzystuje moduł `secrets` (CSPRNG) - gwarantuje obecność małych i wielkich liter, cyfr oraz znaków specjalnych
- **Przechowywanie:** Baza SQLite zapisywana lokalnie - żadne dane nie opuszczają urządzenia
- **Master Password:** Nie jest nigdzie przechowywany - weryfikacja odbywa się poprzez odszyfrowanie tokenu kontrolnego

---

## Wymagania

- Python 3.10+
- Biblioteka `cryptography`

---

## Instalacja

```bash
# Klonowanie repozytorium
git clone <url-repozytorium>
cd Local Password Manager

# Utworzenie środowiska wirtualnego (zalecane)
python -m venv .venv

# Aktywacja środowiska
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# Instalacja zależności
pip install -r requirements.txt
```

---

## Uruchomienie

```bash
python main.py
```

Przy pierwszym uruchomieniu użytkownik jest poproszony o utworzenie **Master Password** (min. 8 znaków). Musi je zapamiętać - hasła nie da się odzyskać.

---

## Użytkowanie

Po zalogowaniu dostępne jest interaktywne menu:

```
--- MENU ---
  [1] Dodaj hasło
  [2] Pobierz hasło
  [3] Lista serwisów
  [4] Generuj hasło
  [5] Usuń hasło
  [6] Wyjście
```

### Dodawanie hasła

Użytkownik podaje nazwę serwisu, login oraz hasło. Może wpisać hasło ręcznie lub nacisnąć `g`, aby wygenerować silne hasło o wybranej długości.

### Pobieranie hasła

Użytkownik wpisuje nazwę serwisu (lub jej fragment) - aplikacja wyświetla odszyfrowane hasło na **10 sekund**, a następnie automatycznie "czyści" ekran.

### Generator haseł

Samodzielny generator pozwala wygenerować bezpieczne hasło o długości 8-128 znaków bez zapisywania go w bazie.

---

## Struktura projektu

```
Local Password Manager/
├── main.py            # Interfejs CLI — menu, logowanie, obsługa akcji
├── crypto.py          # Szyfrowanie / deszyfrowanie, derivacja klucza (PBKDF2 + Fernet)
├── db.py              # Warstwa dostępu do bazy danych SQLite
├── generator.py       # Kryptograficznie bezpieczny generator haseł
├── requirements.txt   # Zależności Pythona
└── passwords.db       # Zaszyfrowana baza danych (tworzona przy pierwszym uruchomieniu)
```

---
