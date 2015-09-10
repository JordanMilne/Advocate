class AdvocateException(Exception):
    pass


class UnacceptableAddressException(AdvocateException):
    pass


class BlacklistException(AdvocateException):
    pass
