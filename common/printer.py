import sys

def logger_p(name,match,unit=None):
    if unit is not None:
        print(f"{name} : {match} {unit}")
    else:
        print(f"{name} : {match}")