-- =========================================================================
-- پروژه امنیت اطلاعات — راه‌اندازی پایگاه‌داده در Supabase
-- این کد را در Dashboard → SQL Editor → New query پیست کنید و Run بزنید
-- =========================================================================


-- =========================================================================
-- نکته امنیتی شماره ۱: ساخت جدول profiles + فعال کردن RLS
-- =========================================================================
-- رمز عبور هرگز در این جدول ذخیره نمی‌شود. رمز به‌صورت هش‌شده توسط
-- خود سرویس Auth سوپابیس در جدول داخلی و غیرقابل‌مشاهده auth.users
-- نگه‌داری می‌شود (نکته شماره ۳).

create table public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  username text unique not null,
  phone text,
  avatar_url text,
  created_at timestamptz default now()
);

-- *** فعال‌سازی Row Level Security — همین خط را در ویدیو نشان دهید ***
alter table public.profiles enable row level security;


-- =========================================================================
-- نکته امنیتی شماره ۲: Policy ها — هر کاربر فقط به ردیف خودش دسترسی دارد
-- =========================================================================
create policy "Users can view own profile"
on public.profiles for select
using ( auth.uid() = id );

create policy "Users can update own profile"
on public.profiles for update
using ( auth.uid() = id );

create policy "Users can insert own profile"
on public.profiles for insert
with check ( auth.uid() = id );


-- =========================================================================
-- ساخت خودکار ردیف profile بعد از ثبت‌نام (از روی متادیتای signUp)
-- =========================================================================
create function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, username, phone)
  values (
    new.id,
    new.raw_user_meta_data->>'username',
    new.raw_user_meta_data->>'phone'
  );
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();


-- =========================================================================
-- توابع کمکی برای امکان ورود با «نام کاربری یا ایمیل»
-- این دو تابع security definer هستند، یعنی از RLS عبور می‌کنند، اما
-- عمداً بسیار محدود طراحی شده‌اند: فقط یک مقدار boolean یا فقط یک
-- رشته‌ی ایمیل برمی‌گردانند، نه کل ردیف یا اطلاعات سایر کاربران.
-- یعنی همان اصل «حداقل دسترسی لازم» (نکته ۲) اینجا هم رعایت شده.
-- =========================================================================

-- آیا این نام کاربری قبلاً گرفته شده؟ (برای فرم ثبت‌نام)
create or replace function public.is_username_taken(check_username text)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles where username = check_username
  );
$$;
grant execute on function public.is_username_taken(text) to anon, authenticated;

-- پیدا کردن ایمیل از روی نام کاربری (فقط در لحظه‌ی ورود استفاده می‌شود)
create or replace function public.get_email_by_username(uname text)
returns text
language sql
security definer
set search_path = public, auth
as $$
  select u.email
  from auth.users u
  join public.profiles p on p.id = u.id
  where p.username = uname
  limit 1;
$$;
grant execute on function public.get_email_by_username(text) to anon, authenticated;


-- =========================================================================
-- نکته امنیتی شماره ۵: محدودسازی نوع و حجم فایل‌های آپلودی (Storage)
-- =========================================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'avatars', 'avatars', true,
  2097152, -- 2 مگابایت بر حسب بایت
  array['image/png', 'image/jpeg', 'image/webp']
);

create policy "Users can upload own avatar"
on storage.objects for insert
with check (
  bucket_id = 'avatars'
  and auth.uid()::text = (storage.foldername(name))[1]
);

create policy "Avatar images are publicly viewable"
on storage.objects for select
using ( bucket_id = 'avatars' );
