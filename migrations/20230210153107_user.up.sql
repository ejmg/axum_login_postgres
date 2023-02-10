-- Add up migration script here

create table users (
    id              bigserial primary key,
    username        text not null,
    pw_hash         text not null
)