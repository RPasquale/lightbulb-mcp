-- Additive customer-application upgrade. Install AFTER customer_saas_v1.sql.
CREATE TABLE IF NOT EXISTS lightbulb_saas.workspace_owners (
    app_id uuid NOT NULL,workspace_ref text NOT NULL,email text NOT NULL,
    PRIMARY KEY(app_id,workspace_ref),
    FOREIGN KEY(app_id,workspace_ref,email) REFERENCES lightbulb_saas.memberships
);
CREATE TABLE IF NOT EXISTS lightbulb_saas.self_service_actions (
    app_id uuid NOT NULL,workspace_ref text NOT NULL,subject_ref text NOT NULL,action_ref uuid NOT NULL,
    version bigint NOT NULL, state jsonb NOT NULL,
    PRIMARY KEY(app_id,workspace_ref,action_ref),
    FOREIGN KEY(app_id,workspace_ref) REFERENCES lightbulb_saas.workspaces
);
CREATE TABLE IF NOT EXISTS lightbulb_saas.invitation_deliveries (
    app_id uuid NOT NULL,workspace_ref text NOT NULL,email text NOT NULL,expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK(state IN ('sending','sent','unknown')),
    PRIMARY KEY(app_id,workspace_ref,email,expires_at)
);
CREATE OR REPLACE FUNCTION lightbulb_saas.first_invitation_owner_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
BEGIN
    -- The first invitation of a newly approved workspace is its reviewed customer owner.
    -- Existing workspaces need an explicit operator-reviewed owner row, never an inferred user.
    IF EXISTS(SELECT 1 FROM lightbulb_saas.workspaces WHERE app_id=NEW.app_id AND workspace_ref=NEW.workspace_ref AND revision=1)
      AND (SELECT count(*) FROM lightbulb_saas.memberships WHERE app_id=NEW.app_id AND workspace_ref=NEW.workspace_ref)=1 THEN
      INSERT INTO lightbulb_saas.workspace_owners VALUES(NEW.app_id,NEW.workspace_ref,NEW.email) ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS customer_saas_first_invitation_owner ON lightbulb_saas.memberships;
CREATE TRIGGER customer_saas_first_invitation_owner AFTER INSERT ON lightbulb_saas.memberships
FOR EACH ROW EXECUTE FUNCTION lightbulb_saas.first_invitation_owner_v1();

CREATE OR REPLACE FUNCTION lightbulb_saas.customer_context_v1(a uuid,w text,s text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; m lightbulb_saas.memberships;
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user) THEN RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    SELECT * INTO STRICT x FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w;
    SELECT * INTO STRICT m FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND subject_ref=s AND accepted_at IS NOT NULL;
    RETURN lightbulb_saas.snapshot_v1(a,w,x.customer_ref,m.email) || jsonb_build_object('can_manage',
      EXISTS(SELECT 1 FROM lightbulb_saas.workspace_owners WHERE app_id=a AND workspace_ref=w AND email=m.email));
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.self_service_state_v1(a uuid,w text,s text,r uuid,v bigint,new_state jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
DECLARE ctx jsonb; old lightbulb_saas.self_service_actions;
BEGIN
    ctx:=lightbulb_saas.customer_context_v1(a,w,s);
    IF NOT (ctx->>'can_manage')::boolean THEN RAISE EXCEPTION 'SAAS_OWNER_REQUIRED'; END IF;
    PERFORM 1 FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w FOR UPDATE;
    SELECT * INTO old FROM lightbulb_saas.self_service_actions WHERE app_id=a AND workspace_ref=w AND action_ref=r FOR UPDATE;
    IF FOUND AND old.subject_ref<>s THEN RAISE EXCEPTION 'SAAS_ACTION_OWNER'; END IF;
    IF new_state IS NULL THEN
      IF old.action_ref IS NULL THEN RAISE EXCEPTION 'SAAS_ACTION_MISSING'; END IF;
      RETURN jsonb_build_object('version',old.version,'state',old.state);
    END IF;
    IF jsonb_typeof(new_state) IS DISTINCT FROM 'object' OR octet_length(new_state::text)>20000
      OR EXISTS(SELECT 1 FROM jsonb_object_keys(new_state) k WHERE k NOT IN ('phase','request','approval_ref'))
      OR jsonb_typeof(new_state->'request') IS DISTINCT FROM 'object'
      OR new_state->>'phase' IS NULL
      OR new_state->>'phase' NOT IN ('prepared','pending_approval','posting','completed','unknown','failed','review_required') THEN RAISE EXCEPTION 'SAAS_ACTION_STATE'; END IF;
    IF old.action_ref IS NULL THEN
      IF v<>0 OR new_state->>'phase'<>'prepared' THEN RAISE EXCEPTION 'SAAS_ACTION_VERSION'; END IF;
      INSERT INTO lightbulb_saas.self_service_actions VALUES(a,w,s,r,1,new_state);
    ELSE
      IF old.version IS DISTINCT FROM v OR old.state->'request' IS DISTINCT FROM new_state->'request'
        OR NOT ((old.state->>'phase' IN ('prepared','pending_approval') AND new_state->>'phase'='posting')
          OR (old.state->>'phase'='posting' AND new_state->>'phase' IN ('pending_approval','completed','unknown','failed','review_required')))
        THEN RAISE EXCEPTION 'SAAS_ACTION_VERSION'; END IF;
      UPDATE lightbulb_saas.self_service_actions SET state=new_state,version=version+1 WHERE app_id=a AND workspace_ref=w AND action_ref=r;
    END IF;
    RETURN jsonb_build_object('version',v+1,'state',new_state);
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.claim_invitation_delivery_v1(a uuid,w text,e text,x timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user) THEN RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.memberships m JOIN lightbulb_saas.workspaces z USING(app_id,workspace_ref)
      WHERE m.app_id=a AND m.workspace_ref=w AND m.email=e AND m.expires_at=x AND x>clock_timestamp() AND m.accepted_at IS NULL AND z.status='active') THEN RETURN false; END IF;
    INSERT INTO lightbulb_saas.invitation_deliveries VALUES(a,w,e,x,'sending') ON CONFLICT DO NOTHING;
    RETURN FOUND;
END $$;
CREATE OR REPLACE FUNCTION lightbulb_saas.finish_invitation_delivery_v1(a uuid,w text,e text,x timestamptz,result text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND identity_role=session_user)
      OR result NOT IN ('sent','unknown') THEN RAISE EXCEPTION 'SAAS_IDENTITY_AUTHORITY'; END IF;
    UPDATE lightbulb_saas.invitation_deliveries SET state=result WHERE app_id=a AND workspace_ref=w AND email=e AND expires_at=x AND state='sending';
    IF NOT FOUND THEN RAISE EXCEPTION 'SAAS_DELIVERY_STATE'; END IF;
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.get_app_setup_v1(a uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
DECLARE app lightbulb_saas.applications; bad_owner boolean; identity_ready boolean;
BEGIN
    SELECT * INTO STRICT app FROM lightbulb_saas.applications WHERE app_id=a AND connector_role=session_user;
    SELECT EXISTS(SELECT 1 FROM lightbulb_saas.workspaces w LEFT JOIN lightbulb_saas.workspace_owners o USING(app_id,workspace_ref)
      WHERE w.app_id=a AND o.email IS NULL) INTO bad_owner;
    identity_ready:=has_schema_privilege(app.identity_role,'lightbulb_saas','USAGE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.accept_invitation_v1(uuid,text,text,text)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.authorize_subject_v1(uuid,text,text)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.customer_context_v1(uuid,text,text)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.self_service_state_v1(uuid,text,text,uuid,bigint,jsonb)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.pending_invitations_v1(uuid,text,text)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.claim_invitation_delivery_v1(uuid,text,text,timestamp with time zone)','EXECUTE')
      AND has_function_privilege(app.identity_role,'lightbulb_saas.finish_invitation_delivery_v1(uuid,text,text,timestamp with time zone,text)','EXECUTE')
      AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='lightbulb_saas' AND c.relkind IN ('r','p')
          AND (has_table_privilege(app.identity_role,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
            OR has_table_privilege(app.connector_role,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')))
      AND has_function_privilege(app.connector_role,'lightbulb_saas.remove_customer_member_v1(uuid,jsonb)','EXECUTE')
      AND NOT has_function_privilege(app.connector_role,'lightbulb_saas.accept_invitation_v1(uuid,text,text,text)','EXECUTE');
    RETURN jsonb_build_object('schema','lightbulb.customer_saas_setup.v1','application_id',a,
      'kit_version',1,'identity_role_ready',identity_ready,'owner_mappings_complete',NOT bad_owner,
      'ready',identity_ready AND NOT bad_owner);
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.remove_customer_member_v1(a uuid,cmd jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
DECLARE x lightbulb_saas.workspaces; old lightbulb_saas.actions; result jsonb;
  w text:=cmd->>'workspace_ref'; e text:=cmd->>'email';
BEGIN
    IF NOT EXISTS(SELECT 1 FROM lightbulb_saas.applications WHERE app_id=a AND connector_role=session_user) THEN RAISE EXCEPTION 'SAAS_APPLICATION_SCOPE'; END IF;
    PERFORM 1 FROM lightbulb_saas.applications WHERE app_id=a FOR UPDATE;
    IF jsonb_typeof(cmd) IS DISTINCT FROM 'object'
      OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(cmd) key) IS DISTINCT FROM ARRAY['action_ref','customer_ref','email','expected_revision','workspace_ref']
      OR EXISTS(SELECT 1 FROM jsonb_each(cmd) p WHERE jsonb_typeof(p.value) IS DISTINCT FROM CASE WHEN p.key='expected_revision' THEN 'number' ELSE 'string' END)
      OR cmd->>'expected_revision' !~ '^[1-9][0-9]*$' OR w !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR cmd->>'customer_ref' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR cmd->>'action_ref' !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$'
      OR e !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' OR e<>lower(e) OR length(e)>254 THEN RAISE EXCEPTION 'SAAS_INPUT'; END IF;
    SELECT * INTO old FROM lightbulb_saas.actions WHERE app_id=a AND action_ref=cmd->>'action_ref';
    IF FOUND THEN
      IF old.command IS DISTINCT FROM cmd THEN RAISE EXCEPTION 'SAAS_IDEMPOTENCY_CONFLICT'; END IF;
      RETURN old.result;
    END IF;
    SELECT * INTO STRICT x FROM lightbulb_saas.workspaces WHERE app_id=a AND workspace_ref=w FOR UPDATE;
    IF x.customer_ref<>cmd->>'customer_ref' OR x.revision<>(cmd->>'expected_revision')::bigint THEN RAISE EXCEPTION 'SAAS_REVISION_OR_IDENTITY'; END IF;
    IF EXISTS(SELECT 1 FROM lightbulb_saas.workspace_owners WHERE app_id=a AND workspace_ref=w AND email=e) THEN RAISE EXCEPTION 'SAAS_OWNER_REMOVAL_FORBIDDEN'; END IF;
    DELETE FROM lightbulb_saas.memberships WHERE app_id=a AND workspace_ref=w AND email=e;
    IF NOT FOUND THEN RAISE EXCEPTION 'SAAS_MEMBER_MISSING'; END IF;
    UPDATE lightbulb_saas.workspaces SET revision=revision+1 WHERE app_id=a AND workspace_ref=w;
    result:=lightbulb_saas.snapshot_v1(a,w,x.customer_ref,e);
    INSERT INTO lightbulb_saas.actions VALUES(a,cmd->>'action_ref',cmd,result);
    RETURN result;
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA lightbulb_saas FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA lightbulb_saas FROM PUBLIC;
