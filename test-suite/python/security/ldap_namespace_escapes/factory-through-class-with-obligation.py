class Carrier:
    def expose(self): pass
mutate(Carrier)
def collect(request):
    values = set()
    values.add(request.args['dn'])
collect(request)

def unrelated(values):
    return any(value for value in values)
