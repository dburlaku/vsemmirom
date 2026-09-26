-- «Всем миром» — состояние заказа на сервере (этап Э1).
-- Личные данные участников хранятся здесь; оригиналы снимков пойдут в S3 отдельно.

create table if not exists orders (
  id            text primary key,                  -- 128 бит случайности: это и есть секрет ссылки владельца
  pid           text not null unique,              -- публичный идентификатор для участников
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  title         text not null default 'Книга историй',
  occasion      text not null default 'birthday',
  event_date    date,
  tier          text not null default 'Момент',
  tier_price    integer not null default 0,
  status        text not null default 'awaiting',  -- awaiting | paid
  deliv         text not null default 'later',     -- msk | ru | later
  people        integer not null default 1,
  extra_days    integer not null default 0,
  edition       integer not null default 1,
  stage         text not null default 'collect',   -- collect | book-closed
  access        jsonb  not null default '{"collect":true,"invite":true,"public":false}'::jsonb,
  invite_token  text not null unique,
  revoked       boolean not null default false,
  frozen        boolean not null default false,
  closed_at     timestamptz,
  owner_name    text,
  owner_contact text,
  series        jsonb,
  vol_decision  text
);

create table if not exists invites (
  id         text primary key,
  order_id   text not null references orders(id) on delete cascade,
  token      text not null unique,
  name       text not null,
  contact    text not null default '',
  status     text not null default 'draft',        -- draft | sent | joined | contrib | removed
  items      integer not null default 0,
  created_at timestamptz not null default now()
);
create index if not exists invites_order on invites(order_id);

create table if not exists log (
  id       bigserial primary key,
  order_id text not null references orders(id) on delete cascade,
  at       timestamptz not null default now(),
  who      text not null default 'владелец',
  act      text not null,
  info     text not null default ''
);
create index if not exists log_order on log(order_id, id desc);

create table if not exists layouts (
  order_id   text primary key references orders(id) on delete cascade,
  doc        jsonb not null,
  rev        integer not null default 1,
  updated_at timestamptz not null default now()
);

-- входы по общей ссылке: защита от расползания (§4 Приложения А)
create table if not exists hits (
  order_id text not null references orders(id) on delete cascade,
  at       timestamptz not null default now()
);
create index if not exists hits_order on hits(order_id, at desc);
