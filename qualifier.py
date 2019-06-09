import logging
import random
import string

logging.basicConfig(level=logging.CRITICAL)


def generate_password(
        password_length: int = 8,
        has_symbols: bool = False,
        has_uppercase: bool = False,
        ignored_chars: list = None,
        allowed_chars: list = None
) -> str:
    """Generates a random password.

    The password will be exactly `password_length` characters.
    If `has_symbols` is True, the password will contain at least one symbol, such as #, !, or @.
    If `has_uppercase` is True, the password will contain at least one upper case letter.
    """
    if allowed_chars and ignored_chars:
        raise UserWarning('You can not specify both allowed_chars and ignored_chars')

    if allowed_chars:
        logging.debug('Got list of allowed_chars, only using those')
        return ensure_setting(password="".join(allowed_chars), capitalized=has_uppercase, symbol=has_symbols)

    # If short password let ensure_setting() handle it.
    if password_length > 5 and has_uppercase or has_symbols:
        logging.debug('Short password with settings, only using lower case characters and ensure_setting()')
        possible_characters = string.ascii_lowercase
    else:
        possible_characters = string.ascii_uppercase + string.ascii_lowercase + string.punctuation
    if ignored_chars:
        logging.debug('Removing these characters from the possible_characters: %s', ignored_chars)
        possible_characters = possible_characters.replace("".join(ignored_chars), '')
        return ensure_setting(password=random.choices(population=possible_characters, k=password_length),
                              capitalized=has_uppercase,
                              symbol=has_symbols
                              )
    return ensure_setting(password=random.choices(population=possible_characters, k=password_length),
                          capitalized=has_uppercase,
                          symbol=has_symbols
                          )


def ensure_setting(password: str, capitalized: bool = False, symbol: bool = False) -> str:
    """
    Takes a password and ensures it has an upper case letter or symbol, depending on the settings
    """
    logging.info('Got password: %s.', password)
    found = {
        'capitalized': False,
        'symbol': False
    }
    # If capitalized or symbol is not required, we mark them as found to skip code
    if not capitalized:
        found['capitalized'] = True
    if not symbol:
        found['symbol'] = True

    # Check if there is a capitalized letter in the password
    if not found['capitalized'] and not any(x.isupper for x in password):
        logging.debug('There is a capitalized letter in the password already.')
        found['capitalized'] = True
    # Check if there is a symbol in the password
    if not found['symbol'] and any(x in string.punctuation for x in password):
        logging.debug('There is a symbol in the password already.')
        found['symbol'] = True

    password = list(password)
    while not found['capitalized'] or not found['symbol']:
        index = len(password) - 1
        # Starting in the end since a capitalized or symbol as a first letter is
        # considered bad security
        for element in reversed(password):
            if element.islower():
                logging.debug('Found lower case letter: %s', element)
                break
            index -= 1
        if not found['capitalized']:
            logging.debug('Capitalizing %s', password[index])
            password[index] = password[index].capitalize()
            found['capitalized'] = True
        elif not found['symbol']:
            logging.debug('Changing %s into a symbol', password[index])
            password[index] = random.choices(string.punctuation, k=1)[0]
            found['symbol'] = True

    logging.info('Generated password: %s', password)
    return "".join(password)
