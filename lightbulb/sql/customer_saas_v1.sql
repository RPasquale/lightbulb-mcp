-- Install in the CUSTOMER APPLICATION database, as a dedicated non-login schema owner.
-- This is not a Lightbulb control-plane migration. See customer SaaS integration guide.
CREATE SCHEMA IF NOT EXISTS lightbulb_saas;
REVOKE ALL ON SCHEMA lightbulb_saas FROM PUBLIC;
CREATE TABLE IF NOT EXISTS lightbulb_saas.applications (
    app_id uuid PRIMARY KEY,
    connector_role name NOT NULL UNIQUE,
    identity_role name NOT NULL UNIQUE,
    CHECK (connector_role <> identity_role)
);
CREATE TABLE IF NOT EXISTS lightbulb_saas.workspaces (
    app_id uuid NOT NULL REFERENCES lightbulb_saas.applications,
    workspace_ref text NOT NULL,
    customer_ref text NOT NULL,
    plan_ref text NOT NULL,
    features jsonb NOT NULL,
    seat_limit integer NOT NULL CHECK (seat_limit BETWEEN 1 AND 100000),
    status text NOT NULL CHECK (status IN ('active','suspended')),
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (app_id, workspace_ref),
    UNIQUE (app_id, customer_ref)
);
CREATE TABLE IF NOT EXISTS lightbulb_saas.memberships (
    app_id uuid NOT NULL,
    workspace_ref text NOT NULL,
    email text NOT NULL,
    subject_ref text,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    PRIMARY KEY (app_id,workspace_ref,email),
    UNIQUE (app_id,workspace_ref,subject_ref),
    FOREIGN KEY (app_id,workspace_ref) REFERENCES lightbulb_saas.workspaces,
    CHECK ((subject_ref IS NULL) = (accepted_at IS NULL))
);
CREATE TABLE IF NOT EXISTS lightbulb_saas.actions (
    app_id uuid NOT NULL,
    action_ref text NOT NULL,
    command jsonb NOT NULL,
    result jsonb NOT NULL,
    PRIMARY KEY(app_id,action_ref)
);

CREATE OR REPLACE FUNCTION lightbulb_saas.snapshot_v1(a uuid,w text,c text,e text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; m lightbulb_saas.memberships; active_count bigint; pending_count bigint;
BEGIN
    SELECT * INTO STRICT x FROM lightbulb_saas.workspaces
      WHERE app_id=a AND workspace_ref=w AND customer_ref=c;
    SELECT * INTO m FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND email=e;
    SELECT count(*) FILTER (WHERE accepted_at IS NOT NULL),
           count(*) FILTER (WHERE accepted_at IS NULL AND expires_at>clock_timestamp())
      INTO active_count,pending_count FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w;
    RETURN jsonb_build_object('schema','lightbulb.customer_saas_workspace.v1','id',w,
      'application_id',a,'customer_identity',c,'member_email',e,'plan_ref',x.plan_ref,
      'features',x.features,'seat_limit',x.seat_limit,'status',x.status,'revision',x.revision,
      'member_count',active_count,'pending_invitation_count',pending_count,
      'member_status',CASE WHEN m.accepted_at IS NOT NULL THEN 'active'
        WHEN m.email IS NULL THEN 'absent' WHEN m.expires_at<=clock_timestamp() THEN 'expired' ELSE 'pending' END,
      'access_active',x.status='active' AND m.accepted_at IS NOT NULL);
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.get_workspace_v1(a uuid,w text,c text,e text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND connector_role=session_user) THEN
      RAISE EXCEPTION 'SAAS_APPLICATION_SCOPE'; END IF;
    RETURN lightbulb_saas.snapshot_v1(a,w,c,e);
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.apply_workspace_v1(a uuid, cmd jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; old lightbulb_saas.actions; result jsonb;
  w text:=cmd->>'workspace_ref'; c text:=cmd->>'customer_ref'; e text:=cmd->>'email';
  action text:=cmd->>'action'; expires timestamptz; occupied bigint;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND connector_role=session_user) THEN
      RAISE EXCEPTION 'SAAS_APPLICATION_SCOPE'; END IF;
    -- Serialize commands across this application, including creation and duplicate action IDs.
    PERFORM 1 FROM lightbulb_saas.applications WHERE app_id=a FOR UPDATE;
    IF cmd IS NULL OR jsonb_typeof(cmd)<>'object' THEN RAISE EXCEPTION 'SAAS_INPUT'; END IF;
    IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(cmd) key) <>
       ARRAY['action','action_ref','customer_ref','email','expected_revision','features','invitation_expires_at','plan_ref','seat_limit','workspace_ref'] THEN
      RAISE EXCEPTION 'SAAS_INPUT_KEYS'; END IF;
    IF EXISTS(SELECT 1 FROM jsonb_each(cmd) p WHERE p.key<>'features' AND
      (p.value='null'::jsonb OR jsonb_typeof(p.value)<>CASE WHEN p.key IN ('seat_limit','expected_revision') THEN 'number' ELSE 'string' END))
      OR cmd->>'seat_limit' !~ '^[0-9]+$' OR cmd->>'expected_revision' !~ '^[0-9]+$' THEN RAISE EXCEPTION 'SAAS_INPUT_TYPES'; END IF;
    IF w !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$' OR c !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR cmd->>'action_ref' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR e !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' OR e<>lower(e) OR length(e)>254
      OR cmd->>'plan_ref' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR (cmd->>'seat_limit')::integer NOT BETWEEN 1 AND 100000
      OR (cmd->>'expected_revision')::bigint<0 OR jsonb_typeof(cmd->'features')<>'array'
      OR jsonb_array_length(cmd->'features')>20 THEN RAISE EXCEPTION 'SAAS_INPUT'; END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(cmd->'features') f WHERE jsonb_typeof(f)<>'string' OR f#>>'{}' !~ '^[a-z][a-z0-9_.-]{0,63}$')
      OR (SELECT count(*) FROM jsonb_array_elements(cmd->'features')) <>
         (SELECT count(DISTINCT f) FROM jsonb_array_elements(cmd->'features') f) THEN RAISE EXCEPTION 'SAAS_FEATURES'; END IF;
    SELECT * INTO old FROM lightbulb_saas.actions WHERE app_id=a AND action_ref=cmd->>'action_ref';
    IF FOUND THEN
      IF old.command<>cmd THEN RAISE EXCEPTION 'SAAS_IDEMPOTENCY_CONFLICT'; END IF;
      RETURN old.result;
    END IF;
    SELECT * INTO x FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w FOR UPDATE;
    IF action='create' THEN
      IF FOUND OR (cmd->>'expected_revision')::bigint<>0 THEN RAISE EXCEPTION 'SAAS_WORKSPACE_EXISTS'; END IF;
      INSERT INTO lightbulb_saas.workspaces VALUES(a,w,c,cmd->>'plan_ref',cmd->'features',(cmd->>'seat_limit')::integer,'active',1);
    ELSE
      IF NOT FOUND OR x.customer_ref<>c OR x.revision<>(cmd->>'expected_revision')::bigint THEN RAISE EXCEPTION 'SAAS_REVISION_OR_IDENTITY'; END IF;
      IF action NOT IN ('configure','invite','suspend','reactivate') THEN RAISE EXCEPTION 'SAAS_ACTION'; END IF;
      IF action<>'configure' AND (x.plan_ref<>cmd->>'plan_ref' OR x.features<>cmd->'features' OR x.seat_limit<>(cmd->>'seat_limit')::integer) THEN
        RAISE EXCEPTION 'SAAS_UNAPPROVED_CONFIGURATION'; END IF;
      SELECT count(*) INTO occupied FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w
        AND (accepted_at IS NOT NULL OR expires_at>clock_timestamp());
      IF (cmd->>'seat_limit')::integer<occupied THEN RAISE EXCEPTION 'SAAS_SEAT_LIMIT'; END IF;
      IF action='invite' AND x.status<>'active' THEN RAISE EXCEPTION 'SAAS_SUSPENDED'; END IF;
      UPDATE lightbulb_saas.workspaces SET revision=revision+1,
        plan_ref=cmd->>'plan_ref',features=cmd->'features',seat_limit=(cmd->>'seat_limit')::integer,
        status=CASE WHEN action='suspend' THEN 'suspended' WHEN action='reactivate' THEN 'active' ELSE status END
        WHERE app_id=a AND workspace_ref=w;
    END IF;
    IF action IN ('create','invite') THEN
      expires:=(cmd->>'invitation_expires_at')::timestamptz;
      IF expires<=clock_timestamp() OR expires>clock_timestamp()+interval '30 days' THEN RAISE EXCEPTION 'SAAS_INVITATION_EXPIRY'; END IF;
      SELECT count(*) INTO occupied FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w
        AND (accepted_at IS NOT NULL OR expires_at>clock_timestamp());
      IF occupied>=(cmd->>'seat_limit')::integer THEN RAISE EXCEPTION 'SAAS_SEAT_LIMIT'; END IF;
      INSERT INTO lightbulb_saas.memberships(app_id,workspace_ref,email,expires_at) VALUES(a,w,e,expires)
        ON CONFLICT(app_id,workspace_ref,email) DO UPDATE SET expires_at=EXCLUDED.expires_at
        WHERE lightbulb_saas.memberships.accepted_at IS NULL AND lightbulb_saas.memberships.expires_at<=clock_timestamp();
      IF NOT FOUND THEN RAISE EXCEPTION 'SAAS_INVITATION_ALREADY_EXISTS'; END IF;
    END IF;
    result:=lightbulb_saas.snapshot_v1(a,w,c,e);
    INSERT INTO lightbulb_saas.actions VALUES(a,cmd->>'action_ref',cmd,result);
    RETURN result;
END $$;

-- Only the application's authenticated identity service receives EXECUTE here. It must
-- supply its verified email and immutable authentication subject, never request-body claims.
CREATE OR REPLACE FUNCTION lightbulb_saas.accept_invitation_v1(a uuid,w text,e text,s text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; m lightbulb_saas.memberships; occupied bigint;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user)
      OR s IS NULL OR length(s) NOT BETWEEN 1 AND 200 OR e IS NULL THEN RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    SELECT * INTO STRICT x FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w FOR UPDATE;
    IF x.status<>'active' THEN RAISE EXCEPTION 'SAAS_SUSPENDED'; END IF;
    SELECT * INTO STRICT m FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND email=e FOR UPDATE;
    IF m.accepted_at IS NOT NULL THEN
      IF m.subject_ref<>s THEN RAISE EXCEPTION 'SAAS_SUBJECT_CONFLICT'; END IF;
    ELSE
      IF m.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'SAAS_INVITATION_EXPIRED'; END IF;
      SELECT count(*) INTO occupied FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND accepted_at IS NOT NULL;
      IF occupied>=x.seat_limit THEN RAISE EXCEPTION 'SAAS_SEAT_LIMIT'; END IF;
      UPDATE lightbulb_saas.memberships SET subject_ref=s,accepted_at=clock_timestamp() WHERE app_id=a AND workspace_ref=w AND email=e;
      UPDATE lightbulb_saas.workspaces SET revision=revision+1 WHERE app_id=a AND workspace_ref=w;
    END IF;
    RETURN lightbulb_saas.snapshot_v1(a,w,x.customer_ref,e);
END $$;

-- Application requests authorize against this function on EVERY protected request;
-- a missing membership or suspension immediately produces access_active=false.
CREATE OR REPLACE FUNCTION lightbulb_saas.authorize_subject_v1(a uuid,w text,s text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; e text;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user) THEN
      RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    SELECT * INTO STRICT x FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w;
    SELECT email INTO e FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND subject_ref=s AND accepted_at IS NOT NULL;
    RETURN jsonb_build_object('access_active',x.status='active' AND e IS NOT NULL,
      'features',CASE WHEN x.status='active' AND e IS NOT NULL THEN x.features ELSE '[]'::jsonb END,
      'seat_limit',x.seat_limit,'plan_ref',x.plan_ref,'revision',x.revision);
END $$;

-- Application-owned delivery polls these records. It sends its own authenticated sign-in URL,
-- never a Lightbulb-minted token; delivery must be idempotent on app/workspace/email/expiry.
CREATE OR REPLACE FUNCTION lightbulb_saas.pending_invitations_v1(a uuid, after_workspace text, after_email text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,lightbulb_saas AS $$
DECLARE result jsonb;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user)
      OR after_workspace IS NULL OR after_email IS NULL THEN RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    SELECT coalesce(jsonb_agg(to_jsonb(p)),'[]'::jsonb) INTO result FROM (
      SELECT m.workspace_ref,m.email,m.expires_at FROM lightbulb_saas.memberships m
      JOIN lightbulb_saas.workspaces w USING(app_id,workspace_ref)
      WHERE m.app_id=a AND m.accepted_at IS NULL AND m.expires_at>clock_timestamp() AND w.status='active'
        AND (m.workspace_ref,m.email)>(after_workspace,after_email)
      ORDER BY m.workspace_ref,m.email LIMIT 100
    ) p;
    RETURN result;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA lightbulb_saas FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA lightbulb_saas FROM PUBLIC;
