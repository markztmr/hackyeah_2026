-- products, employees, salaries. Spec section 6 (data labels), section 13. Owner: Person 3.
--
-- employees.id and salaries.employee_id are TEXT and equal the user IDs in
-- policy.yaml (anna, marek, piotr, ...), because :current_user is bound to the
-- authenticated user's ID and compared to these owner columns (spec section 5).

CREATE TABLE products (
    id       INTEGER PRIMARY KEY,
    name     TEXT    NOT NULL,
    category TEXT    NOT NULL,
    price    REAL    NOT NULL CHECK (price >= 0)
);

CREATE TABLE employees (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    title      TEXT NOT NULL
);

CREATE TABLE salaries (
    employee_id TEXT    PRIMARY KEY REFERENCES employees (id),
    salary      INTEGER NOT NULL CHECK (salary > 0),
    currency    TEXT    NOT NULL DEFAULT 'PLN'
);
