# server/data.py

candidates = [
    {'id': 1, 'name': 'Alice', 'lastname': 'Smith'},
    {'id': 2,'name': 'Bob', 'lastname': 'Johnson'},
    {'id': 3,'name': 'Carol', 'lastname': 'Williams'},
    {'id': 4,'name': 'David', 'lastname': 'Brown'},
    {'id': 5,'name': 'Eve', 'lastname': 'Jones'},
]

# Static voter list with fixed IDs
static_voters = [
    {'id': 'ID1001', 'name': 'John',    'lastname': 'Doe',     'birthdate': '1990-01-01'},
    {'id': 'ID1002', 'name': 'Jane',    'lastname': 'Roe',     'birthdate': '1992-02-02'},
    {'id': 'ID1003', 'name': 'Max',     'lastname': 'Payne',   'birthdate': '1985-03-03'},
    {'id': 'ID1004', 'name': 'Lara',    'lastname': 'Croft',   'birthdate': '1988-04-04'},
    {'id': 'ID1005', 'name': 'Sam',     'lastname': 'Fisher',  'birthdate': '1978-05-05'},
    {'id': 'ID1006', 'name': 'Ada',     'lastname': 'Wong',    'birthdate': '1991-06-06'},
    {'id': 'ID1007', 'name': 'Gordon',  'lastname': 'Freeman', 'birthdate': '1980-07-07'},
    {'id': 'ID1008', 'name': 'Jill',    'lastname': 'Valentine','birthdate': '1983-08-08'},
    {'id': 'ID1009', 'name': 'Leon',    'lastname': 'Kennedy', 'birthdate': '1987-09-09'},
    {'id': 'ID1010', 'name': 'Claire',  'lastname': 'Redfield','birthdate': '1993-10-10'},
]

# List for public display (without IDs)
voters = [
    {'name': v['name'], 'lastname': v['lastname'], 'birthdate': v['birthdate']}
    for v in static_voters
]

# Confidential mapping for server-side ID matching
confidential_voters = {
    v['id']: {'name': v['name'], 'lastname': v['lastname'], 'birthdate': v['birthdate']}
    for v in static_voters
}

eligibility_requests = []
commits = []
reveals = []
