import re
def expose(): pass
mutate(expose)
re.search('dc=example', request.args['filter'])

def unrelated(values):
    return any(value for value in values)
