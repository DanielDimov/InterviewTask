create sequence id_generator;

create table "user"
(
    id       bigint not null default nextval('id_generator') primary key,
    email    varchar(200),
    password varchar(64),
    role     varchar(20),
    active   boolean,
    unique (email)
);
create index user_email on "user" (email);

create table merchant
(
    id              bigint       not null default nextval('id_generator') primary key,
    name            varchar(100) not null,
    description     varchar(1000),
    user_id         bigint       not null references "user" (id),
    transaction_sum money,
    unique (name)
);
create index merchant_name on merchant (name);
create index merchant_user_id on merchant (user_id);
