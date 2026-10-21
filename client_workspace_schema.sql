-- CLIENT WORKSPACE SCHEMA v2 (matches your index.html: clients + client_memberships)
-- Safe to run more than once. Run in Supabase: SQL Editor > New query > paste all > Run

-- 1. CLIENTS + MEMBERSHIPS (reuses yours if they already exist)
create table if not exists public.clients (
  id bigint generated always as identity primary key,
  name text not null,
  slug text unique,
  created_at timestamptz not null default now()
);
alter table public.clients add column if not exists slug text;

-- id type of clients, so the new tables match whatever you already have
do $$
declare idtype text;
begin
  select format_type(a.atttypid, a.atttypmod) into idtype
  from pg_attribute a
  where a.attrelid = 'public.clients'::regclass and a.attname = 'id' and not a.attisdropped;

  if to_regclass('public.client_memberships') is null then
    execute format($f$
      create table public.client_memberships (
        client_id %s not null references public.clients(id) on delete cascade,
        user_id uuid not null references auth.users(id) on delete cascade,
        role text not null default 'client',
        primary key (client_id, user_id)
      )$f$, idtype);
  end if;

  if to_regclass('public.portal_tasks') is null then
    execute format($f$
      create table public.portal_tasks (
        id bigint generated always as identity primary key,
        client_id %s not null references public.clients(id) on delete cascade,
        category text not null check (category in ('content_approval','business_support','campaign')),
        title text not null,
        platform text,
        format text,
        details text,
        preview_url text,
        due_date date,
        status text not null default 'draft'
          check (status in ('draft','for_approval','approved','changes_requested','in_progress','done')),
        client_feedback text,
        responded_at timestamptz,
        responded_by uuid references auth.users(id),
        notion_url text,
        created_at timestamptz not null default now(),
        updated_at timestamptz not null default now()
      )$f$, idtype);
  end if;
end $$;

create index if not exists portal_tasks_client_status on public.portal_tasks (client_id, status);

create table if not exists public.portal_task_events (
  id bigint generated always as identity primary key,
  task_id bigint not null references public.portal_tasks(id) on delete cascade,
  actor_id uuid references auth.users(id),
  action text not null,
  note text,
  created_at timestamptz not null default now()
);

-- admins (you). Only the database owner and the function below can read this.
create table if not exists public.portal_admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- 2. FUNCTIONS
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.portal_admins where user_id = auth.uid());
$$;

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists portal_tasks_touch on public.portal_tasks;
create trigger portal_tasks_touch before update on public.portal_tasks
for each row execute function public.touch_updated_at();

-- the ONLY way a client changes a task: approve, or request changes with a note
create or replace function public.respond_to_task(p_task_id bigint, p_decision text, p_note text default null)
returns public.portal_tasks language plpgsql security definer set search_path = public as $$
declare t public.portal_tasks;
begin
  if auth.uid() is null then raise exception 'Please log in'; end if;
  if p_decision not in ('approved','changes_requested') then
    raise exception 'Invalid decision';
  end if;
  if p_decision = 'changes_requested' and coalesce(btrim(p_note),'') = '' then
    raise exception 'Please add a note describing the changes';
  end if;

  update public.portal_tasks
     set status = p_decision, client_feedback = p_note,
         responded_at = now(), responded_by = auth.uid()
   where id = p_task_id
     and status = 'for_approval'
     and client_id in (select client_id from public.client_memberships where user_id = auth.uid())
  returning * into t;

  if t.id is null then
    raise exception 'This item is not waiting for your approval';
  end if;

  insert into public.portal_task_events (task_id, actor_id, action, note)
  values (t.id, auth.uid(), p_decision, p_note);
  return t;
end $$;

revoke all on function public.respond_to_task(bigint, text, text) from public, anon;
grant execute on function public.respond_to_task(bigint, text, text) to authenticated;

-- 3. ROW LEVEL SECURITY
alter table public.clients enable row level security;
alter table public.client_memberships enable row level security;
alter table public.portal_tasks enable row level security;
alter table public.portal_task_events enable row level security;
alter table public.portal_admins enable row level security;

drop policy if exists "wp own membership" on public.client_memberships;
create policy "wp own membership" on public.client_memberships for select to authenticated
  using (user_id = auth.uid() or public.is_admin());

drop policy if exists "wp own client" on public.clients;
create policy "wp own client" on public.clients for select to authenticated
  using (id in (select client_id from public.client_memberships where user_id = auth.uid()) or public.is_admin());

drop policy if exists "wp clients read own tasks" on public.portal_tasks;
create policy "wp clients read own tasks" on public.portal_tasks for select to authenticated
  using ((status <> 'draft' and client_id in (select client_id from public.client_memberships where user_id = auth.uid()))
         or public.is_admin());

drop policy if exists "wp admin manages tasks" on public.portal_tasks;
create policy "wp admin manages tasks" on public.portal_tasks for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists "wp clients read own events" on public.portal_task_events;
create policy "wp clients read own events" on public.portal_task_events for select to authenticated
  using (task_id in (select id from public.portal_tasks) or public.is_admin());

-- 4. AFTER RUNNING (replace the capitalized parts)
-- a) Make yourself admin (you must already have a login):
--    insert into public.portal_admins (user_id)
--    select id from auth.users where email = 'YOUR_EMAIL_HERE';
-- b) Add a client and link their invited login:
--    insert into public.clients (name, slug) values ('CLIENT NAME', 'client-slug');
--    insert into public.client_memberships (client_id, user_id)
--    values ((select id from public.clients where slug = 'client-slug'),
--            (select id from auth.users where email = 'CLIENT_EMAIL_HERE'));
-- c) Add something for them to approve:
--    insert into public.portal_tasks (client_id, category, title, platform, format, status, due_date)
--    values ((select id from public.clients where slug = 'client-slug'),
--            'content_approval', 'Test post', 'Facebook & Instagram', 'Static image', 'for_approval', current_date + 3);
