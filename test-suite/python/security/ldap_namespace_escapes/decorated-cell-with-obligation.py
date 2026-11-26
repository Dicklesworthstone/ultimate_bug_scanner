def collect(request):
    values = {1}
    @decorate
    def expose(): return values
    values.add(request.args['dn'])
collect(request)

def unrelated(values):
    return any(value for value in values)
