-- Additive upgrade after customer_saas_kit_v1.sql. Grant history to the application identity role.
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
      OR EXISTS(SELECT 1 FROM jsonb_object_keys(new_state) k WHERE k NOT IN ('phase','request','approval_ref','receipt','recovery_attempts','next_recovery_at'))
      OR jsonb_typeof(new_state->'request') IS DISTINCT FROM 'object'
      OR new_state->>'phase' IS NULL
      OR new_state->>'phase' NOT IN ('prepared','pending_approval','posting','completed','unknown','failed','review_required') THEN RAISE EXCEPTION 'SAAS_ACTION_STATE'; END IF;
    -- Older application versions complete posting without a retained receipt.
    -- Only the new recovery transition requires it, preserving rolling upgrades.
    IF old.state->>'phase' IN ('unknown','review_required') AND new_state->>'phase'='completed'
      AND jsonb_typeof(new_state->'receipt') IS DISTINCT FROM 'object'
      THEN RAISE EXCEPTION 'SAAS_ACTION_RECEIPT_REQUIRED'; END IF;
    IF coalesce((new_state->>'recovery_attempts')::integer,0) NOT BETWEEN 0 AND 3
      OR coalesce((new_state->>'recovery_attempts')::integer,0)<coalesce((old.state->>'recovery_attempts')::integer,0)
      THEN RAISE EXCEPTION 'SAAS_RECOVERY_BUDGET'; END IF;
    IF old.action_ref IS NULL THEN
      IF v<>0 OR new_state->>'phase'<>'prepared' THEN RAISE EXCEPTION 'SAAS_ACTION_VERSION'; END IF;
      INSERT INTO lightbulb_saas.self_service_actions VALUES(a,w,s,r,1,new_state);
    ELSE
      IF old.version IS DISTINCT FROM v OR old.state->'request' IS DISTINCT FROM new_state->'request'
        OR (old.state ? 'approval_ref' AND old.state->'approval_ref' IS DISTINCT FROM new_state->'approval_ref')
        OR NOT ((old.state->>'phase' IN ('prepared','pending_approval') AND new_state->>'phase'='posting')
          OR (old.state->>'phase'='posting' AND new_state->>'phase' IN ('pending_approval','completed','unknown','failed','review_required'))
          OR (old.state->>'phase'='unknown' AND new_state->>'phase' IN ('unknown','review_required','completed'))
          OR (old.state->>'phase'='review_required' AND new_state->>'phase'='completed'))
        THEN RAISE EXCEPTION 'SAAS_ACTION_VERSION'; END IF;
      UPDATE lightbulb_saas.self_service_actions SET state=new_state,version=version+1 WHERE app_id=a AND workspace_ref=w AND action_ref=r;
    END IF;
    RETURN jsonb_build_object('version',v+1,'state',new_state);
END $$;

CREATE OR REPLACE FUNCTION lightbulb_saas.self_service_history_v1(a uuid,w text,s text,c uuid,n integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,lightbulb_saas AS $$
DECLARE ctx jsonb; result jsonb;
BEGIN
    ctx:=lightbulb_saas.customer_context_v1(a,w,s);
    IF NOT (ctx->>'can_manage')::boolean THEN RAISE EXCEPTION 'SAAS_OWNER_REQUIRED'; END IF;
    IF n IS NULL OR n<1 OR n>101 THEN RAISE EXCEPTION 'SAAS_HISTORY_LIMIT'; END IF;
    SELECT coalesce(jsonb_agg(item ORDER BY action_ref),'[]'::jsonb) INTO result FROM (
      SELECT action_ref,jsonb_build_object('action_ref',action_ref,
        'action',state->'request'->'metadata'->>'customer_action',
        'phase',CASE WHEN state->>'phase'='posting' THEN 'unknown' ELSE state->>'phase' END) item
      FROM lightbulb_saas.self_service_actions
      WHERE app_id=a AND workspace_ref=w AND subject_ref=s AND (c IS NULL OR action_ref>c)
      ORDER BY action_ref LIMIT n
    ) page;
    RETURN result;
END $$;
REVOKE ALL ON FUNCTION lightbulb_saas.self_service_history_v1(uuid,text,text,uuid,integer) FROM PUBLIC;

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
      AND has_function_privilege(app.identity_role,'lightbulb_saas.self_service_history_v1(uuid,text,text,uuid,integer)','EXECUTE')
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
