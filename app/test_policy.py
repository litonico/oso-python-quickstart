import pytest
from oso import Oso, ForbiddenError
from .models import User, Role, Repository

oso = Oso()
oso.register_class(User)
oso.register_class(Repository)

oso.load_files(["app/main.polar"])

# Testing denied combinations of actor, action, resource
def test_maintainers_cannot_delete_repos():
    repo = Repository.get_by_name("gmail")
    maintainer = User([Role(name="maintainer", repository=repo)])
    with pytest.raises(ForbiddenError):
        oso.authorize(maintainer, "delete", repo)

# Testing allowed combinations of actor, action, resource
def test_admins_can_delete_repos():
    repo = Repository.get_by_name("gmail")
    user = User([Role(name="admin", repository=repo)])
    assert oso.authorize(user, "delete", repo) == None

# Testing all combinations of roles and actions
def test_combinations_of_role_and_action():
    repository = Repository.get_by_name("gmail")

    combinations = [
        ("contributor", "read",   repository, True ),
        ("contributor", "push",   repository, False),
        ("contributor", "delete", repository, False),
        ("maintainer",  "read",   repository, True ),
        ("maintainer",  "push",   repository, True ),
        ("maintainer",  "delete", repository, False),
        ("admin",       "read",   repository, True ),
        ("admin",       "push",   repository, True ),
        ("admin",       "delete", repository, True ),
    ]

    errors = []
    for role, action, repo, expected in combinations:
        user = User([Role(name=role, repository=repo)])
        try:
            oso.authorize(user, action, repo)
            actual = True
        except:
            actual = False

        if actual != expected:
            errors.append(role + ":" + action)

    assert errors == []

# Policy unit tests: query_rule
def test_admin_users_have_admin_roles_on_repos():
    repo = Repository.get_by_name("gmail")
    user = User([Role(name="admin", repository=repo)])
    assert oso.query_rule("has_role", user, "admin", repo)
