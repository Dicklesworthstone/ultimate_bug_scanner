def collect(request):
    values = {1}
    def expose(): return values
    mutate(expose)
    values.add(request.args['dn'])
collect(request)

def unrelated(values):
    return any(value for value in values)
