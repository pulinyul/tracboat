# -*- coding: utf-8 -*-

from peewee import *
from playhouse.postgres_ext import *

database_proxy = Proxy()

class UnknownField(object):
    pass

class BaseModel(Model):
    class Meta:
        database = database_proxy

class AbuseReports(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    message = TextField(null=True)
    message_html = TextField(null=True)
    reporter_id = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(index=True, null=True)

    class Meta:
        table_name = 'abuse_reports'

class ApplicationSettingTerms(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    terms = TextField()
    terms_html = TextField(null=True)

    class Meta:
        table_name = 'application_setting_terms'

# Possible reference cycle: projects
# Possible reference cycle: projects
class PushRules(BaseModel):
    author_email_regex = CharField(null=True)
    branch_name_regex = CharField(null=True)
    commit_committer_check = BooleanField(null=True)
    commit_message_negative_regex = CharField(null=True)
    commit_message_regex = CharField(null=True)
    created_at = DateTimeField(null=True)
    delete_branch_regex = CharField(null=True)
    deny_delete_tag = BooleanField(null=True)
    file_name_regex = CharField(null=True)
    force_push_regex = CharField(null=True)
    is_sample = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    max_file_size = IntegerField(constraints=[SQL("DEFAULT 0")])
    member_check = BooleanField(constraints=[SQL("DEFAULT false")])
    prevent_secrets = BooleanField(constraints=[SQL("DEFAULT false")])
#    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    regexp_uses_re2 = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    reject_unsigned_commits = BooleanField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'push_rules'

class Namespaces(BaseModel):
    allow_descendants_override_disabled_shared_runners = BooleanField(constraints=[SQL("DEFAULT false")])
    auto_devops_enabled = BooleanField(null=True)
    avatar = CharField(null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    custom_project_templates_group = ForeignKeyField(column_name='custom_project_templates_group_id', field='id', model='self', null=True)
    default_branch_protection = SmallIntegerField(null=True)
    delayed_project_removal = BooleanField(constraints=[SQL("DEFAULT false")])
    description = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    description_html = TextField(null=True)
    emails_disabled = BooleanField(null=True)
    extra_shared_runners_minutes_limit = IntegerField(null=True)
    #file_template_project = ForeignKeyField(column_name='file_template_project_id', field='id', model=Projects, null=True)
    last_ci_minutes_notification_at = DateTimeField(null=True)
    last_ci_minutes_usage_notification_level = IntegerField(null=True)
    ldap_sync_error = CharField(null=True)
    ldap_sync_last_successful_update_at = DateTimeField(index=True, null=True)
    ldap_sync_last_sync_at = DateTimeField(null=True)
    ldap_sync_last_update_at = DateTimeField(index=True, null=True)
    ldap_sync_status = CharField(constraints=[SQL("DEFAULT 'ready'::character varying")])
    lfs_enabled = BooleanField(null=True)
    max_artifacts_size = IntegerField(null=True)
    max_pages_size = IntegerField(null=True)
    max_personal_access_token_lifetime = IntegerField(null=True)
    membership_lock = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    mentions_disabled = BooleanField(null=True)
    name = CharField(index=True)
    owner_id = IntegerField(index=True, null=True)
    parent_id = IntegerField(null=True)
    path = CharField(index=True)
    project_creation_level = IntegerField(null=True)
    push_rule = ForeignKeyField(column_name='push_rule_id', field='id', model=PushRules, null=True, unique=True)
    repository_size_limit = BigIntegerField(null=True)
    request_access_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    require_two_factor_authentication = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    runners_token = CharField(null=True, unique=True)
    runners_token_encrypted = CharField(null=True, unique=True)
    saml_discovery_token = CharField(null=True)
    share_with_group_lock = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    shared_runners_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    shared_runners_minutes_limit = IntegerField(null=True)
    subgroup_creation_level = IntegerField(constraints=[SQL("DEFAULT 1")], null=True)
    traversal_ids = ArrayField(constraints=[SQL("DEFAULT '{}'::integer[]")], field_class=IntegerField, index=True)
    two_factor_grace_period = IntegerField(constraints=[SQL("DEFAULT 48")])
    type = CharField(null=True)
    unlock_membership_to_ldap = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField(constraints=[SQL("DEFAULT 20")])

    class Meta:
        table_name = 'namespaces'
        indexes = (
            (('custom_project_templates_group', 'type'), False),
            (('custom_project_templates_group', 'type'), False),
            (('name', 'parent_id'), True),
            (('name', 'parent_id'), True),
            (('parent_id', 'id'), True),
            (('parent_id', 'id'), True),
            (('shared_runners_minutes_limit', 'extra_shared_runners_minutes_limit'), False),
            (('shared_runners_minutes_limit', 'extra_shared_runners_minutes_limit'), False),
            (('type', 'id'), False),
            (('type', 'id'), False),
        )

class Users(BaseModel):
    accepted_term = ForeignKeyField(column_name='accepted_term_id', field='id', model=ApplicationSettingTerms, null=True)
    admin = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    admin_email_unsubscribed_at = DateTimeField(null=True)
    auditor = BooleanField(constraints=[SQL("DEFAULT false")])
    avatar = CharField(null=True)
    can_create_group = BooleanField(constraints=[SQL("DEFAULT true")])
    can_create_team = BooleanField(constraints=[SQL("DEFAULT true")])
    color_scheme_id = IntegerField(constraints=[SQL("DEFAULT 1")])
    commit_email = CharField(null=True)
    confirmation_sent_at = DateTimeField(null=True)
    confirmation_token = CharField(null=True, unique=True)
    confirmed_at = DateTimeField(null=True)
    consumed_timestep = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    created_by_id = IntegerField(null=True)
    current_sign_in_at = DateTimeField(null=True)
    current_sign_in_ip = CharField(null=True)
    dashboard = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    email = CharField(constraints=[SQL("DEFAULT ''::character varying")], index=True)
    email_opted_in = BooleanField(null=True)
    email_opted_in_at = DateTimeField(null=True)
    email_opted_in_ip = CharField(null=True)
    email_opted_in_source_id = IntegerField(null=True)
    encrypted_otp_secret = CharField(null=True)
    encrypted_otp_secret_iv = CharField(null=True)
    encrypted_otp_secret_salt = CharField(null=True)
    encrypted_password = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    external = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    failed_attempts = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    feed_token = CharField(index=True, null=True)
    first_name = CharField(null=True)
    group_view = IntegerField(index=True, null=True)
    hide_no_password = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    hide_no_ssh_key = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    hide_project_limit = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    include_private_contributions = BooleanField(null=True)
    incoming_email_token = CharField(index=True, null=True)
    last_activity_on = DateField(null=True)
    last_credential_check_at = DateTimeField(null=True)
    last_name = CharField(null=True)
    last_sign_in_at = DateTimeField(null=True)
    last_sign_in_ip = CharField(null=True)
    layout = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    linkedin = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    location = CharField(null=True)
    locked_at = DateTimeField(null=True)
    managing_group = ForeignKeyField(column_name='managing_group_id', field='id', model=Namespaces, null=True)
    name = CharField(index=True, null=True)
    note = TextField(null=True)
    notification_email = CharField(null=True)
    notified_of_own_activity = BooleanField(null=True)
    organization = CharField(null=True)
    otp_backup_codes = TextField(null=True)
    otp_grace_period_started_at = DateTimeField(null=True)
    otp_required_for_login = BooleanField(constraints=[SQL("DEFAULT false")])
    password_automatically_set = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    password_expires_at = DateTimeField(null=True)
    preferred_language = CharField(null=True)
    private_profile = BooleanField(constraints=[SQL("DEFAULT false")])
    project_view = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    projects_limit = IntegerField()
    public_email = CharField(constraints=[SQL("DEFAULT ''::character varying")], index=True)
    remember_created_at = DateTimeField(null=True)
    require_two_factor_authentication_from_group = BooleanField(constraints=[SQL("DEFAULT false")])
    reset_password_sent_at = DateTimeField(null=True)
    reset_password_token = CharField(null=True, unique=True)
    roadmap_layout = SmallIntegerField(null=True)
    role = SmallIntegerField(null=True)
    sign_in_count = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    skype = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    state = CharField(index=True, null=True)
    static_object_token = CharField(null=True, unique=True)
    theme_id = SmallIntegerField(null=True)
    twitter = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    two_factor_grace_period = IntegerField(constraints=[SQL("DEFAULT 48")])
    unconfirmed_email = CharField(index=True, null=True)
    unlock_token = CharField(null=True, unique=True)
    updated_at = DateTimeField(null=True)
    user_type = SmallIntegerField(index=True, null=True)
    username = CharField(index=True, null=True)
    website_url = CharField(constraints=[SQL("DEFAULT ''::character varying")])

    class Meta:
        table_name = 'users'
        indexes = (
            (('state', 'user_type'), False),
            (('state', 'user_type'), False),
        )

class Shards(BaseModel):
    name = CharField(unique=True)

    class Meta:
        table_name = 'shards'

# Possible reference cycle: projects
class PoolRepositories(BaseModel):
    disk_path = CharField(null=True, unique=True)
    id = BigAutoField()
    shard = ForeignKeyField(column_name='shard_id', field='id', model=Shards)
#    source_project = ForeignKeyField(column_name='source_project_id', field='id', model=Projects, null=True)
    state = CharField(null=True)

    class Meta:
        table_name = 'pool_repositories'
        indexes = (
            (('source_project', 'shard'), True),
        )

class Projects(BaseModel):
    approvals_before_merge = IntegerField(constraints=[SQL("DEFAULT 0")])
    archived = BooleanField(constraints=[SQL("DEFAULT false")])
    auto_cancel_pending_pipelines = IntegerField(constraints=[SQL("DEFAULT 1")])
    autoclose_referenced_issues = BooleanField(null=True)
    avatar = CharField(null=True)
    bfg_object_map = CharField(null=True)
    build_allow_git_fetch = BooleanField(constraints=[SQL("DEFAULT true")])
    build_coverage_regex = CharField(null=True)
    build_timeout = IntegerField(constraints=[SQL("DEFAULT 3600")])
    cached_markdown_version = IntegerField(null=True)
    ci_config_path = CharField(null=True)
    container_registry_enabled = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    creator_id = IntegerField(null=True)
    delete_error = TextField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    detected_repository_languages = BooleanField(null=True)
    disable_overriding_approvers_per_merge_request = BooleanField(null=True)
    emails_disabled = BooleanField(null=True)
    external_authorization_classification_label = CharField(null=True)
    external_webhook_token = CharField(null=True)
    has_external_issue_tracker = BooleanField(null=True)
    has_external_wiki = BooleanField(null=True)
    import_source = CharField(null=True)
    import_type = CharField(null=True)
    import_url = CharField(null=True)
    issues_template = TextField(null=True)
    jobs_cache_index = IntegerField(null=True)
    last_activity_at = DateTimeField(null=True)
    last_repository_check_at = DateTimeField(index=True, null=True)
    last_repository_check_failed = BooleanField(index=True, null=True)
    last_repository_updated_at = DateTimeField(index=True, null=True)
    lfs_enabled = BooleanField(null=True)
    marked_for_deletion_at = DateField(index=True, null=True)
    marked_for_deletion_by_user = ForeignKeyField(column_name='marked_for_deletion_by_user_id', field='id', model=Users, null=True)
    max_artifacts_size = IntegerField(null=True)
    max_pages_size = IntegerField(null=True)
    merge_requests_author_approval = BooleanField(null=True)
    merge_requests_disable_committers_approval = BooleanField(null=True)
    merge_requests_ff_only_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    merge_requests_rebase_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    merge_requests_template = TextField(null=True)
    mirror = BooleanField(constraints=[SQL("DEFAULT false")])
    mirror_last_successful_update_at = DateTimeField(index=True, null=True)
    mirror_last_update_at = DateTimeField(null=True)
    mirror_overwrites_diverged_branches = BooleanField(null=True)
    mirror_trigger_builds = BooleanField(constraints=[SQL("DEFAULT false")])
    mirror_user_id = IntegerField(index=True, null=True)
    name = CharField(index=True, null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)
    only_allow_merge_if_all_discussions_are_resolved = BooleanField(null=True)
    only_allow_merge_if_pipeline_succeeds = BooleanField(constraints=[SQL("DEFAULT false")])
    only_mirror_protected_branches = BooleanField(null=True)
    packages_enabled = BooleanField(null=True)
    pages_https_only = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    path = CharField(index=True, null=True)
    pending_delete = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    pool_repository = ForeignKeyField(column_name='pool_repository_id', field='id', model=PoolRepositories, null=True)
    printing_merge_request_link_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    public_builds = BooleanField(constraints=[SQL("DEFAULT true")])
    pull_mirror_available_overridden = BooleanField(null=True)
    pull_mirror_branch_prefix = CharField(null=True)
    remote_mirror_available_overridden = BooleanField(null=True)
    remove_source_branch_after_merge = BooleanField(null=True)
    repository_read_only = BooleanField(null=True)
    repository_size_limit = BigIntegerField(null=True)
    repository_storage = CharField(constraints=[SQL("DEFAULT 'default'::character varying")], index=True)
    request_access_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    require_password_to_approve = BooleanField(null=True)
    reset_approvals_on_push = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    resolve_outdated_diff_discussions = BooleanField(null=True)
    runners_token = CharField(index=True, null=True)
    runners_token_encrypted = CharField(index=True, null=True)
    service_desk_enabled = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    shared_runners_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    star_count = IntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    storage_version = SmallIntegerField(null=True)
    suggestion_commit_message = CharField(null=True)
    updated_at = DateTimeField(null=True)
    visibility_level = IntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'projects'
        indexes = (
            (('created_at', 'id'), False),
            (('created_at', 'id'), False),
            (('created_at', 'id'), False),
            (('created_at', 'id'), False),
            (('created_at', 'id'), False),
            (('created_at', 'id'), False),
            (('creator_id', 'created_at'), False),
            (('creator_id', 'created_at', 'id'), False),
            (('creator_id', 'id'), False),
            (('id', 'created_at'), False),
            (('id', 'created_at'), False),
            (('id', 'creator_id', 'created_at'), False),
            (('id', 'repository_storage', 'last_repository_updated_at'), False),
            (('import_type', 'creator_id', 'created_at'), False),
            (('last_activity_at', 'id'), False),
            (('last_activity_at', 'id'), False),
            (('last_activity_at', 'id'), False),
            (('name', 'id'), False),
            (('name', 'id'), False),
            (('name', 'id'), False),
            (('namespace', 'id'), False),
            (('path', 'id'), False),
            (('path', 'id'), False),
            (('path', 'id'), False),
            (('repository_storage', 'created_at'), False),
            (('updated_at', 'id'), False),
            (('updated_at', 'id'), False),
            (('updated_at', 'id'), False),
        )

PushRules.project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
Namespaces.file_template_project = ForeignKeyField(column_name='file_template_project_id', field='id', model=Projects, null=True)
PoolRepositories.source_project = ForeignKeyField(column_name='source_project_id', field='id', model=Projects, null=True)

class Environments(BaseModel):
    auto_stop_at = DateTimeField(null=True)
    created_at = DateTimeField(null=True)
    environment_type = CharField(null=True)
    external_url = CharField(null=True)
    name = CharField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    slug = CharField()
    state = CharField(constraints=[SQL("DEFAULT 'available'::character varying")])
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'environments'
        indexes = (
            (('project', 'name'), True),
            (('project', 'slug'), True),
            (('project', 'state', 'environment_type'), False),
            (('state', 'auto_stop_at'), False),
        )

class Milestones(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    due_date = DateField(index=True, null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    iid = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    start_date = DateField(null=True)
    state = CharField(null=True)
    title = CharField(index=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'milestones'
        indexes = (
            (('project', 'iid'), True),
            (('project', 'iid'), True),
        )

class Epics(BaseModel):
    assignee = ForeignKeyField(column_name='assignee_id', field='id', model=Users, null=True)
    author = ForeignKeyField(backref='users_author_set', column_name='author_id', field='id', model=Users)
    cached_markdown_version = IntegerField(null=True)
    closed_at = DateTimeField(null=True)
    closed_by = ForeignKeyField(backref='users_closed_by_set', column_name='closed_by_id', field='id', model=Users, null=True)
    confidential = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    created_at = DateTimeField()
    description = TextField(null=True)
    description_html = TextField(null=True)
    due_date_fixed = DateField(null=True)
    due_date_is_fixed = BooleanField(null=True)
    due_date_sourcing_epic = ForeignKeyField(column_name='due_date_sourcing_epic_id', field='id', model='self', null=True)
    due_date_sourcing_milestone = ForeignKeyField(column_name='due_date_sourcing_milestone_id', field='id', model=Milestones, null=True)
    end_date = DateField(index=True, null=True)
    external_key = CharField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    iid = IntegerField(index=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by_id = IntegerField(index=True, null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], index=True, null=True)
    parent = ForeignKeyField(backref='epics_parent_set', column_name='parent_id', field='id', model='self', null=True)
    relative_position = IntegerField(null=True)
    start_date = DateField(index=True, null=True)
    start_date_fixed = DateField(null=True)
    start_date_is_fixed = BooleanField(null=True)
    start_date_sourcing_epic = ForeignKeyField(backref='epics_start_date_sourcing_epic_set', column_name='start_date_sourcing_epic_id', field='id', model='self', null=True)
    start_date_sourcing_milestone = ForeignKeyField(backref='milestones_start_date_sourcing_milestone_set', column_name='start_date_sourcing_milestone_id', field='id', model=Milestones, null=True)
    state_id = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    title = CharField()
    title_html = CharField()
    updated_at = DateTimeField()
    updated_by_id = IntegerField(null=True)

    class Meta:
        table_name = 'epics'
        indexes = (
            (('group'), False),
            (('group', 'external_key'), True),
            (('group', 'iid'), True),
        )

class Sprints(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    due_date = DateField(index=True, null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    id = BigAutoField()
    iid = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    start_date = DateField(null=True)
    state_enum = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    title = TextField(index=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'sprints'
        indexes = (
            (('group'), False),
            (('group', 'title'), True),
            (('project'), False),
            (('project', 'iid'), True),
            (('project', 'title'), True),
        )

class Issues(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    blocking_issues_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    cached_markdown_version = IntegerField(null=True)
    closed_at = DateTimeField(null=True)
    closed_by = ForeignKeyField(backref='users_closed_by_set', column_name='closed_by_id', field='id', model=Users, null=True)
    confidential = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    created_at = DateTimeField(null=True)
    description = TextField(index=False, null=True)
    #description = TSVectorField(index=True,null=True)
    description_html = TextField(null=True)
    discussion_locked = BooleanField(null=True)
    due_date = DateField(null=True)
    duplicated_to = ForeignKeyField(column_name='duplicated_to_id', field='id', model='self', null=True)
    external_key = CharField(null=True)
    health_status = SmallIntegerField(index=True, null=True)
    iid = IntegerField(null=True)
    issue_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by_id = IntegerField(index=True, null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], index=True, null=True)
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones, null=True)
    moved_to = ForeignKeyField(backref='issues_moved_to_set', column_name='moved_to_id', field='id', model='self', null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    promoted_to_epic = ForeignKeyField(column_name='promoted_to_epic_id', field='id', model=Epics, null=True)
    relative_position = IntegerField(null=True)
    service_desk_reply_to = CharField(null=True)
    sprint = ForeignKeyField(column_name='sprint_id', field='id', model=Sprints, null=True)
    state_id = SmallIntegerField(constraints=[SQL("DEFAULT 1")], index=True)
    time_estimate = IntegerField(null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    updated_by = ForeignKeyField(backref='users_updated_by_set', column_name='updated_by_id', field='id', model=Users, null=True)
    weight = IntegerField(null=True)

    class Meta:
        table_name = 'issues'
        indexes = (
            (('author', 'id', 'created_at'), False),
            (('project', 'closed_at'), False),
            (('project', 'created_at'), False),
            (('project', 'created_at', 'id', 'state_id'), False),
            (('project', 'due_date', 'id', 'state_id'), False),
            (('project', 'external_key'), True),
            (('project', 'iid'), True),
            (('project', 'relative_position', 'state_id', 'id'), False),
            (('project', 'state_id', 'blocking_issues_count'), False),
            (('project', 'updated_at', 'id', 'state_id'), False),
        )

class PrometheusMetrics(BaseModel):
    common = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    created_at = DateTimeField()
    dashboard_path = TextField(null=True)
    group = IntegerField()
    identifier = CharField(null=True, unique=True)
    legend = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    query = CharField()
    title = CharField()
    unit = CharField()
    updated_at = DateTimeField()
    y_label = CharField()

    class Meta:
        table_name = 'prometheus_metrics'
        indexes = (
            (('identifier', 'project'), True),
        )

class PrometheusAlerts(BaseModel):
    created_at = DateTimeField()
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments)
    operator = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    prometheus_metric = ForeignKeyField(column_name='prometheus_metric_id', field='id', model=PrometheusMetrics)
    runbook_url = TextField(null=True)
    threshold = DoubleField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'prometheus_alerts'
        indexes = (
            (('project', 'prometheus_metric', 'environment'), True),
        )

class AlertManagementAlerts(BaseModel):
    created_at = DateTimeField()
    description = TextField(null=True)
    ended_at = DateTimeField(null=True)
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments, null=True)
    events = IntegerField(constraints=[SQL("DEFAULT 1")])
    fingerprint = BlobField(null=True)
    hosts = ArrayField(constraints=[SQL("DEFAULT '{}'::text[]")], field_class=TextField)
    id = BigAutoField()
    iid = IntegerField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    monitoring_tool = TextField(null=True)
    payload = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    prometheus_alert = ForeignKeyField(column_name='prometheus_alert_id', field='id', model=PrometheusAlerts, null=True)
    service = TextField(null=True)
    severity = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    started_at = DateTimeField()
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    title = TextField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'alert_management_alerts'
        indexes = (
            (('project', 'fingerprint'), True),
            (('project', 'iid'), True),
        )

class AlertManagementAlertAssignees(BaseModel):
    alert = ForeignKeyField(column_name='alert_id', field='id', model=AlertManagementAlerts)
    id = BigAutoField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'alert_management_alert_assignees'
        indexes = (
            (('user', 'alert'), True),
        )

class CiRefs(BaseModel):
    id = BigAutoField()
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    ref_path = TextField()
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'ci_refs'
        indexes = (
            (('project', 'ref_path'), True),
        )

class ExternalPullRequests(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    pull_request_iid = IntegerField()
    source_branch = CharField()
    source_repository = CharField()
    source_sha = BlobField()
    status = SmallIntegerField()
    target_branch = CharField()
    target_repository = CharField()
    target_sha = BlobField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'external_pull_requests'
        indexes = (
            (('project', 'source_branch', 'target_branch'), True),
        )

# Possible reference cycle: merge_requests
class CiPipelineSchedules(BaseModel):
    active = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    created_at = DateTimeField(null=True)
    cron = CharField(null=True)
    cron_timezone = CharField(null=True)
    description = CharField(null=True)
    next_run_at = DateTimeField(null=True)
    owner = ForeignKeyField(column_name='owner_id', field='id', model=Users, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    ref = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_pipeline_schedules'
        indexes = (
            (('next_run_at', 'active'), False),
        )

class CiPipelines(BaseModel):
    auto_canceled_by = ForeignKeyField(column_name='auto_canceled_by_id', field='id', model='self', null=True)
    before_sha = CharField(null=True)
    ci_ref = ForeignKeyField(column_name='ci_ref_id', field='id', model=CiRefs, null=True)
    committed_at = DateTimeField(null=True)
    config_source = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    duration = IntegerField(null=True)
    external_pull_request = ForeignKeyField(column_name='external_pull_request_id', field='id', model=ExternalPullRequests, null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    iid = IntegerField(null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    locked = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
#    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    pipeline_schedule = ForeignKeyField(column_name='pipeline_schedule_id', field='id', model=CiPipelineSchedules, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    protected = BooleanField(null=True)
    ref = CharField(null=True)
    sha = CharField(null=True)
    source = IntegerField(null=True)
    source_sha = BlobField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(null=True)
    tag = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    target_sha = BlobField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(null=True)
    yaml_errors = TextField(null=True)

    class Meta:
        table_name = 'ci_pipelines'
        indexes = (
            (('ci_ref', 'id'), False),
            (('project', 'created_at'), False),
            (('project', 'id'), False),
            (('project', 'iid'), True),
            (('project', 'ref', 'id'), False),
            (('project', 'ref', 'status', 'id'), False),
            (('project', 'sha'), False),
            (('project', 'source'), False),
            (('project', 'status', 'config_source'), False),
            (('project', 'status', 'created_at'), False),
            (('project', 'status', 'updated_at'), False),
            (('project', 'user_id', 'status', 'ref'), False),
            (('status', 'id'), False),
            (('user_id', 'created_at', 'config_source'), False),
            (('user_id', 'created_at', 'source'), False),
        )

# Possible reference cycle: merge_requests
class MergeRequestDiffs(BaseModel):
    base_commit_sha = CharField(null=True)
    commits_count = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    external_diff = CharField(null=True)
    external_diff_store = IntegerField(constraints=[SQL("DEFAULT 1")], index=True, null=True)
    files_count = SmallIntegerField(null=True)
    head_commit_sha = CharField(null=True)
#    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    real_size = CharField(null=True)
    start_commit_sha = CharField(null=True)
    state = CharField(null=True)
    stored_externally = BooleanField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'merge_request_diffs'
        indexes = (
            (('merge_request', 'id'), False),
        )

class MergeRequests(BaseModel):
    allow_maintainer_to_push = BooleanField(null=True)
    approvals_before_merge = IntegerField(null=True)
    assignee = ForeignKeyField(column_name='assignee_id', field='id', model=Users, null=True)
    author = ForeignKeyField(backref='users_author_set', column_name='author_id', field='id', model=Users, null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True, null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    discussion_locked = BooleanField(null=True)
    head_pipeline = ForeignKeyField(column_name='head_pipeline_id', field='id', model=CiPipelines, null=True)
    iid = IntegerField(null=True)
    in_progress_merge_commit_sha = CharField(null=True)
    last_edited_at = DateTimeField(null=True)
    last_edited_by_id = IntegerField(null=True)
    latest_merge_request_diff = ForeignKeyField(column_name='latest_merge_request_diff_id', field='id', model=MergeRequestDiffs, null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], index=True, null=True)
    merge_commit_sha = CharField(null=True)
    merge_error = TextField(null=True)
    merge_jid = CharField(null=True)
    merge_params = TextField(null=True)
    merge_ref_sha = BlobField(null=True)
    merge_status = CharField(constraints=[SQL("DEFAULT 'unchecked'::character varying")])
    merge_user = ForeignKeyField(backref='users_merge_user_set', column_name='merge_user_id', field='id', model=Users, null=True)
    merge_when_pipeline_succeeds = BooleanField(constraints=[SQL("DEFAULT false")])
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones, null=True)
    rebase_commit_sha = CharField(null=True)
    rebase_jid = CharField(null=True)
    source_branch = CharField(index=True)
    source_project = ForeignKeyField(column_name='source_project_id', field='id', model=Projects, null=True)
    sprint = ForeignKeyField(column_name='sprint_id', field='id', model=Sprints, null=True)
    squash = BooleanField(constraints=[SQL("DEFAULT false")])
    squash_commit_sha = BlobField(null=True)
    state_id = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    target_branch = CharField(index=True)
    target_project = ForeignKeyField(backref='projects_target_project_set', column_name='target_project_id', field='id', model=Projects)
    time_estimate = IntegerField(null=True)
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(null=True)
    updated_by = ForeignKeyField(backref='users_updated_by_set', column_name='updated_by_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'merge_requests'
        indexes = (
            (('id', 'merge_jid'), False),
            (('source_project', 'source_branch'), False),
            (('source_project', 'source_branch'), False),
            (('state_id', 'merge_status'), False),
            (('target_project', 'created_at', 'id'), False),
            (('target_project', 'iid'), False),
            (('target_project', 'iid'), False),
            (('target_project', 'iid'), False),
            (('target_project', 'iid'), True),
            (('target_project', 'iid', 'state_id'), False),
            (('target_project', 'merge_commit_sha', 'id'), False),
            (('target_project', 'target_branch'), False),
        )

MergeRequestDiffs.merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
CiPipelines.merge_request = ForeignKeyField(column_name='merge_request_id', null=True, model=MergeRequests, to_field='id')

class Reviews(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'reviews'

class Notes(BaseModel):
    attachment = CharField(null=True)
    author_id = IntegerField(null=True)
    cached_markdown_version = IntegerField(null=True)
    change_position = TextField(null=True)
    commit_id = CharField(index=True, null=True)
    confidential = BooleanField(null=True)
    created_at = DateTimeField(index=True, null=True)
    discussion_id = CharField(index=True, null=True)
    line_code = CharField(index=True, null=True)
    #note = TextField(index=True, null=True)
    note = TextField(index=False, null=True)
    note_html = TextField(null=True)
    noteable_id = IntegerField(null=True)
    noteable_type = CharField(null=True)
    original_position = TextField(null=True)
    position = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    resolved_at = DateTimeField(null=True)
    resolved_by_id = IntegerField(null=True)
    resolved_by_push = BooleanField(null=True)
    review = ForeignKeyField(column_name='review_id', field='id', model=Reviews, null=True)
    st_diff = TextField(null=True)
    system = BooleanField(constraints=[SQL("DEFAULT false")])
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    updated_by_id = IntegerField(null=True)

    class Meta:
        table_name = 'notes'
        indexes = (
            (('author_id', 'created_at', 'id'), False),
            (('id', 'noteable_type'), False),
            (('noteable_id', 'noteable_type'), False),
            (('project', 'id'), False),
            (('project', 'noteable_type'), False),
        )

class AlertManagementAlertUserMentions(BaseModel):
    alert_management_alert = ForeignKeyField(column_name='alert_management_alert_id', field='id', model=AlertManagementAlerts, unique=True)
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)

    class Meta:
        table_name = 'alert_management_alert_user_mentions'
        indexes = (
            (('alert_management_alert', 'note'), True),
        )

class AlertManagementHttpIntegrations(BaseModel):
    active = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    encrypted_token = TextField()
    encrypted_token_iv = TextField()
    endpoint_identifier = TextField()
    id = BigAutoField()
    name = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'alert_management_http_integrations'
        indexes = (
            (('active', 'project', 'endpoint_identifier'), True),
        )

class Services(BaseModel):
    active = BooleanField(constraints=[SQL("DEFAULT false")])
    alert_events = BooleanField(null=True)
    category = CharField(constraints=[SQL("DEFAULT 'common'::character varying")])
    comment_detail = SmallIntegerField(null=True)
    comment_on_event_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    commit_events = BooleanField(constraints=[SQL("DEFAULT true")])
    confidential_issues_events = BooleanField(constraints=[SQL("DEFAULT true")])
    confidential_note_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    created_at = DateTimeField(null=True)
    deployment_events = BooleanField(constraints=[SQL("DEFAULT false")])
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    inherit_from = ForeignKeyField(column_name='inherit_from_id', field='id', model='self', null=True)
    instance = BooleanField(constraints=[SQL("DEFAULT false")])
    issues_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    job_events = BooleanField(constraints=[SQL("DEFAULT false")])
    merge_requests_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    note_events = BooleanField(constraints=[SQL("DEFAULT true")])
    pipeline_events = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    properties = TextField(null=True)
    push_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    tag_push_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    template = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    type = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    wiki_page_events = BooleanField(constraints=[SQL("DEFAULT true")], null=True)

    class Meta:
        table_name = 'services'
        indexes = (
            (('group', 'type'), True),
            (('project', 'type'), False),
            (('type', 'id'), False),
            (('type', 'instance'), True),
            (('type', 'template'), True),
        )

class AlertsServiceData(BaseModel):
    created_at = DateTimeField()
    encrypted_token = CharField(null=True)
    encrypted_token_iv = CharField(null=True)
    id = BigAutoField()
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'alerts_service_data'

class AllowedEmailDomains(BaseModel):
    created_at = DateTimeField()
    domain = CharField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'allowed_email_domains'

class Labels(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    description_html = TextField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    template = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    title = CharField(index=True, null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'labels'
        indexes = (
            (('group', 'project', 'title'), True),
            (('group', 'project', 'title'), True),
            (('group', 'title'), False),
            (('group', 'title'), False),
            (('project', 'title'), True),
            (('project', 'title'), True),
            (('type', 'project'), False),
            (('type', 'project'), False),
        )

class AnalyticsCycleAnalyticsGroupValueStreams(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    name = TextField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'analytics_cycle_analytics_group_value_streams'
        indexes = (
            (('group', 'name'), True),
        )

class AnalyticsCycleAnalyticsGroupStages(BaseModel):
    created_at = DateTimeField()
    custom = BooleanField(constraints=[SQL("DEFAULT true")])
    end_event_identifier = IntegerField()
    end_event_label = ForeignKeyField(column_name='end_event_label_id', field='id', model=Labels, null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    group_value_stream = ForeignKeyField(column_name='group_value_stream_id', field='id', model=AnalyticsCycleAnalyticsGroupValueStreams)
    hidden = BooleanField(constraints=[SQL("DEFAULT false")])
    id = BigAutoField()
    name = CharField()
    relative_position = IntegerField(index=True, null=True)
    start_event_identifier = IntegerField()
    start_event_label = ForeignKeyField(backref='labels_start_event_label_set', column_name='start_event_label_id', field='id', model=Labels, null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'analytics_cycle_analytics_group_stages'
        indexes = (
            (('group', 'group_value_stream', 'name'), True),
        )

class AnalyticsCycleAnalyticsProjectStages(BaseModel):
    created_at = DateTimeField()
    custom = BooleanField(constraints=[SQL("DEFAULT true")])
    end_event_identifier = IntegerField()
    end_event_label = ForeignKeyField(column_name='end_event_label_id', field='id', model=Labels, null=True)
    hidden = BooleanField(constraints=[SQL("DEFAULT false")])
    id = BigAutoField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    relative_position = IntegerField(index=True, null=True)
    start_event_identifier = IntegerField()
    start_event_label = ForeignKeyField(backref='labels_start_event_label_set', column_name='start_event_label_id', field='id', model=Labels, null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'analytics_cycle_analytics_project_stages'
        indexes = (
            (('project', 'name'), True),
        )

class AnalyticsDevopsAdoptionSegments(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    last_recorded_at = DateTimeField(null=True)
    name = TextField(unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'analytics_devops_adoption_segments'

class AnalyticsDevopsAdoptionSegmentSelections(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    segment = ForeignKeyField(column_name='segment_id', field='id', model=AnalyticsDevopsAdoptionSegments)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'analytics_devops_adoption_segment_selections'
        indexes = (
            (('group', 'segment'), True),
            (('project', 'segment'), True),
        )

class AnalyticsInstanceStatisticsMeasurements(BaseModel):
    count = BigIntegerField()
    id = BigAutoField()
    identifier = SmallIntegerField()
    recorded_at = DateTimeField()

    class Meta:
        table_name = 'analytics_instance_statistics_measurements'
        indexes = (
            (('identifier', 'recorded_at'), True),
        )

class ProgrammingLanguages(BaseModel):
    color = CharField()
    created_at = DateTimeField()
    name = CharField(unique=True)

    class Meta:
        table_name = 'programming_languages'

class AnalyticsLanguageTrendRepositoryLanguages(BaseModel):
    bytes = IntegerField(constraints=[SQL("DEFAULT 0")])
    file_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    loc = IntegerField(constraints=[SQL("DEFAULT 0")])
    percentage = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    programming_language = ForeignKeyField(column_name='programming_language_id', field='id', model=ProgrammingLanguages)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    snapshot_date = DateField()

    class Meta:
        table_name = 'analytics_language_trend_repository_languages'
        indexes = (
            (('programming_language', 'project', 'snapshot_date'), True),
        )
        primary_key = CompositeKey('programming_language', 'project', 'snapshot_date')

class Appearances(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField()
    description_html = TextField(null=True)
    email_header_and_footer_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    favicon = CharField(null=True)
    footer_message = TextField(null=True)
    footer_message_html = TextField(null=True)
    header_logo = CharField(null=True)
    header_message = TextField(null=True)
    header_message_html = TextField(null=True)
    logo = CharField(null=True)
    message_background_color = TextField(null=True)
    message_font_color = TextField(null=True)
    new_project_guidelines = TextField(null=True)
    new_project_guidelines_html = TextField(null=True)
    profile_image_guidelines = TextField(null=True)
    profile_image_guidelines_html = TextField(null=True)
    title = CharField()
    updated_at = DateTimeField()
    updated_by = IntegerField(null=True)

    class Meta:
        table_name = 'appearances'

class ApplicationSettings(BaseModel):
    abuse_notification_email = CharField(null=True)
    after_sign_out_path = CharField(null=True)
    after_sign_up_text = TextField(null=True)
    after_sign_up_text_html = TextField(null=True)
    akismet_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    allow_group_owners_to_manage_ldap = BooleanField(constraints=[SQL("DEFAULT true")])
    allow_local_requests_from_system_hooks = BooleanField(constraints=[SQL("DEFAULT true")])
    allow_local_requests_from_web_hooks_and_services = BooleanField(constraints=[SQL("DEFAULT false")])
    archive_builds_in_seconds = IntegerField(null=True)
    asset_proxy_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    asset_proxy_url = CharField(null=True)
    asset_proxy_whitelist = TextField(null=True)
    authorized_keys_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    auto_devops_domain = CharField(null=True)
    auto_devops_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    automatic_purchased_storage_allocation = BooleanField(constraints=[SQL("DEFAULT false")])
    cached_markdown_version = IntegerField(null=True)
    check_namespace_plan = BooleanField(constraints=[SQL("DEFAULT false")])
    commit_email_hostname = CharField(null=True)
    compliance_frameworks = ArrayField(constraints=[SQL("DEFAULT '{}'::smallint[]")], field_class=SmallIntegerField)
    container_expiration_policies_enable_historic_entries = BooleanField(constraints=[SQL("DEFAULT false")])
    container_registry_delete_tags_service_timeout = IntegerField(constraints=[SQL("DEFAULT 250")])
    container_registry_expiration_policies_worker_capacity = IntegerField(constraints=[SQL("DEFAULT 0")])
    container_registry_features = ArrayField(constraints=[SQL("DEFAULT '{}'::text[]")], field_class=TextField)
    container_registry_token_expire_delay = IntegerField(constraints=[SQL("DEFAULT 5")], null=True)
    container_registry_vendor = TextField(constraints=[SQL("DEFAULT ''::text")])
    container_registry_version = TextField(constraints=[SQL("DEFAULT ''::text")])
    created_at = DateTimeField(null=True)
    custom_http_clone_url_root = CharField(null=True)
    custom_project_templates_group = ForeignKeyField(column_name='custom_project_templates_group_id', field='id', model=Namespaces, null=True)
    default_artifacts_expire_in = CharField(constraints=[SQL("DEFAULT '0'::character varying")])
    default_branch_name = TextField(null=True)
    default_branch_protection = IntegerField(constraints=[SQL("DEFAULT 2")], null=True)
    default_ci_config_path = CharField(null=True)
    default_group_visibility = IntegerField(null=True)
    default_project_creation = IntegerField(constraints=[SQL("DEFAULT 2")])
    default_project_deletion_protection = BooleanField(constraints=[SQL("DEFAULT false")])
    default_project_visibility = IntegerField(constraints=[SQL("DEFAULT 0")])
    default_projects_limit = IntegerField(null=True)
    default_snippet_visibility = IntegerField(constraints=[SQL("DEFAULT 0")])
    deletion_adjourned_period = IntegerField(constraints=[SQL("DEFAULT 7")])
    diff_max_patch_bytes = IntegerField(constraints=[SQL("DEFAULT 204800")])
    disable_overriding_approvers_per_merge_request = BooleanField(constraints=[SQL("DEFAULT false")])
    disabled_oauth_sign_in_sources = TextField(null=True)
    dns_rebinding_protection_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    domain_allowlist = TextField(null=True)
    domain_denylist = TextField(null=True)
    domain_denylist_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    dsa_key_restriction = IntegerField(constraints=[SQL("DEFAULT '-1'::integer")])
    ecdsa_key_restriction = IntegerField(constraints=[SQL("DEFAULT 0")])
    ed25519_key_restriction = IntegerField(constraints=[SQL("DEFAULT 0")])
    eks_access_key_id = CharField(null=True)
    eks_account_id = CharField(null=True)
    eks_integration_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_analyzers_kuromoji_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_analyzers_kuromoji_search = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_analyzers_smartcn_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_analyzers_smartcn_search = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_aws = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_aws_access_key = CharField(null=True)
    elasticsearch_aws_region = CharField(constraints=[SQL("DEFAULT 'us-east-1'::character varying")], null=True)
    elasticsearch_client_request_timeout = IntegerField(constraints=[SQL("DEFAULT 0")])
    elasticsearch_indexed_field_length_limit = IntegerField(constraints=[SQL("DEFAULT 0")])
    elasticsearch_indexed_file_size_limit_kb = IntegerField(constraints=[SQL("DEFAULT 1024")])
    elasticsearch_indexing = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_limit_indexing = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_max_bulk_concurrency = SmallIntegerField(constraints=[SQL("DEFAULT 10")])
    elasticsearch_max_bulk_size_mb = SmallIntegerField(constraints=[SQL("DEFAULT 10")])
    elasticsearch_pause_indexing = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_replicas = IntegerField(constraints=[SQL("DEFAULT 1")])
    elasticsearch_search = BooleanField(constraints=[SQL("DEFAULT false")])
    elasticsearch_shards = IntegerField(constraints=[SQL("DEFAULT 5")])
    elasticsearch_url = CharField(constraints=[SQL("DEFAULT 'http://localhost:9200'::character varying")], null=True)
    email_additional_text = CharField(null=True)
    email_author_in_body = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    email_restrictions = TextField(null=True)
    email_restrictions_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    enabled_git_access_protocol = CharField(null=True)
    encrypted_akismet_api_key = TextField(null=True)
    encrypted_akismet_api_key_iv = CharField(null=True)
    encrypted_asset_proxy_secret_key = TextField(null=True)
    encrypted_asset_proxy_secret_key_iv = CharField(null=True)
    encrypted_ci_jwt_signing_key = TextField(null=True)
    encrypted_ci_jwt_signing_key_iv = TextField(null=True)
    encrypted_cloud_license_auth_token = TextField(null=True)
    encrypted_cloud_license_auth_token_iv = TextField(null=True)
    encrypted_eks_secret_access_key = TextField(null=True)
    encrypted_eks_secret_access_key_iv = CharField(null=True)
    encrypted_elasticsearch_aws_secret_access_key = TextField(null=True)
    encrypted_elasticsearch_aws_secret_access_key_iv = CharField(null=True)
    encrypted_external_auth_client_key = TextField(null=True)
    encrypted_external_auth_client_key_iv = CharField(null=True)
    encrypted_external_auth_client_key_pass = CharField(null=True)
    encrypted_external_auth_client_key_pass_iv = CharField(null=True)
    encrypted_lets_encrypt_private_key = TextField(null=True)
    encrypted_lets_encrypt_private_key_iv = TextField(null=True)
    encrypted_recaptcha_private_key = TextField(null=True)
    encrypted_recaptcha_private_key_iv = CharField(null=True)
    encrypted_recaptcha_site_key = TextField(null=True)
    encrypted_recaptcha_site_key_iv = CharField(null=True)
    encrypted_secret_detection_token_revocation_token = TextField(null=True)
    encrypted_secret_detection_token_revocation_token_iv = TextField(null=True)
    encrypted_slack_app_secret = TextField(null=True)
    encrypted_slack_app_secret_iv = CharField(null=True)
    encrypted_slack_app_verification_token = TextField(null=True)
    encrypted_slack_app_verification_token_iv = CharField(null=True)
    enforce_namespace_storage_limit = BooleanField(constraints=[SQL("DEFAULT false")])
    enforce_pat_expiration = BooleanField(constraints=[SQL("DEFAULT true")])
    enforce_terms = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    external_auth_client_cert = TextField(null=True)
    external_authorization_service_default_label = CharField(null=True)
    external_authorization_service_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    external_authorization_service_timeout = DoubleField(constraints=[SQL("DEFAULT 0.5")], null=True)
    external_authorization_service_url = CharField(null=True)
    file_template_project = ForeignKeyField(column_name='file_template_project_id', field='id', model=Projects, null=True)
    first_day_of_week = IntegerField(constraints=[SQL("DEFAULT 0")])
    force_pages_access_control = BooleanField(constraints=[SQL("DEFAULT false")])
    geo_node_allowed_ips = CharField(constraints=[SQL("DEFAULT '0.0.0.0/0, ::/0'::character varying")], null=True)
    geo_status_timeout = IntegerField(constraints=[SQL("DEFAULT 10")], null=True)
    gitaly_timeout_default = IntegerField(constraints=[SQL("DEFAULT 55")])
    gitaly_timeout_fast = IntegerField(constraints=[SQL("DEFAULT 10")])
    gitaly_timeout_medium = IntegerField(constraints=[SQL("DEFAULT 30")])
    gitpod_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    gitpod_url = TextField(constraints=[SQL("DEFAULT 'https://gitpod.io/'::text")], null=True)
    grafana_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    grafana_url = CharField(constraints=[SQL("DEFAULT '/-/grafana'::character varying")])
    gravatar_enabled = BooleanField(null=True)
    group_download_export_limit = IntegerField(constraints=[SQL("DEFAULT 1")])
    group_export_limit = IntegerField(constraints=[SQL("DEFAULT 6")])
    group_import_limit = IntegerField(constraints=[SQL("DEFAULT 6")])
    group_owners_can_manage_default_branch_protection = BooleanField(constraints=[SQL("DEFAULT true")])
    hashed_storage_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    health_check_access_token = CharField(null=True)
    help_page_documentation_base_url = TextField(null=True)
    help_page_hide_commercial_content = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    help_page_support_url = CharField(null=True)
    help_page_text = TextField(null=True)
    help_page_text_html = TextField(null=True)
    help_text = TextField(null=True)
    hide_third_party_offers = BooleanField(constraints=[SQL("DEFAULT false")])
    home_page_url = CharField(null=True)
    housekeeping_bitmaps_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    housekeeping_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    housekeeping_full_repack_period = IntegerField(constraints=[SQL("DEFAULT 50")])
    housekeeping_gc_period = IntegerField(constraints=[SQL("DEFAULT 200")])
    housekeeping_incremental_repack_period = IntegerField(constraints=[SQL("DEFAULT 10")])
    html_emails_enabled = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    import_sources = TextField(null=True)
    instance_administration_project = ForeignKeyField(backref='projects_instance_administration_project_set', column_name='instance_administration_project_id', field='id', model=Projects, null=True)
    instance_administrators_group = ForeignKeyField(backref='namespaces_instance_administrators_group_set', column_name='instance_administrators_group_id', field='id', model=Namespaces, null=True)
    issues_create_limit = IntegerField(constraints=[SQL("DEFAULT 0")])
    lets_encrypt_notification_email = CharField(null=True)
    lets_encrypt_terms_of_service_accepted = BooleanField(constraints=[SQL("DEFAULT false")])
    license_trial_ends_on = DateField(null=True)
    local_markdown_version = IntegerField(constraints=[SQL("DEFAULT 0")])
    lock_memberships_to_ldap = BooleanField(constraints=[SQL("DEFAULT false")])
    login_recaptcha_protection_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    maintenance_mode = BooleanField(constraints=[SQL("DEFAULT false")])
    maintenance_mode_message = TextField(null=True)
    max_artifacts_size = IntegerField(constraints=[SQL("DEFAULT 100")])
    max_attachment_size = IntegerField(constraints=[SQL("DEFAULT 10")])
    max_import_size = IntegerField(constraints=[SQL("DEFAULT 50")])
    max_pages_size = IntegerField(constraints=[SQL("DEFAULT 100")])
    max_personal_access_token_lifetime = IntegerField(null=True)
    metrics_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    metrics_host = CharField(constraints=[SQL("DEFAULT 'localhost'::character varying")], null=True)
    metrics_method_call_threshold = IntegerField(constraints=[SQL("DEFAULT 10")], null=True)
    metrics_packet_size = IntegerField(constraints=[SQL("DEFAULT 1")], null=True)
    metrics_pool_size = IntegerField(constraints=[SQL("DEFAULT 16")], null=True)
    metrics_port = IntegerField(constraints=[SQL("DEFAULT 8089")], null=True)
    metrics_sample_interval = IntegerField(constraints=[SQL("DEFAULT 15")], null=True)
    metrics_timeout = IntegerField(constraints=[SQL("DEFAULT 10")], null=True)
    minimum_password_length = IntegerField(constraints=[SQL("DEFAULT 8")])
    mirror_available = BooleanField(constraints=[SQL("DEFAULT true")])
    mirror_capacity_threshold = IntegerField(constraints=[SQL("DEFAULT 50")])
    mirror_max_capacity = IntegerField(constraints=[SQL("DEFAULT 100")])
    mirror_max_delay = IntegerField(constraints=[SQL("DEFAULT 300")])
    new_user_signups_cap = IntegerField(null=True)
    notify_on_unknown_sign_in = BooleanField(constraints=[SQL("DEFAULT true")])
    npm_package_requests_forwarding = BooleanField(constraints=[SQL("DEFAULT true")])
    outbound_local_requests_whitelist = ArrayField(constraints=[SQL("DEFAULT '{}'::character varying[]")], field_class=CharField)
    pages_domain_verification_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    password_authentication_enabled_for_git = BooleanField(constraints=[SQL("DEFAULT true")])
    password_authentication_enabled_for_web = BooleanField(null=True)
    performance_bar_allowed_group_id = IntegerField(null=True)
    plantuml_enabled = BooleanField(null=True)
    plantuml_url = CharField(null=True)
    polling_interval_multiplier = DecimalField(constraints=[SQL("DEFAULT 1")])
    prevent_merge_requests_author_approval = BooleanField(constraints=[SQL("DEFAULT false")])
    prevent_merge_requests_committers_approval = BooleanField(constraints=[SQL("DEFAULT false")])
    productivity_analytics_start_date = DateTimeField(null=True)
    project_download_export_limit = IntegerField(constraints=[SQL("DEFAULT 1")])
    project_export_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    project_export_limit = IntegerField(constraints=[SQL("DEFAULT 6")])
    project_import_limit = IntegerField(constraints=[SQL("DEFAULT 6")])
    prometheus_metrics_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    protected_ci_variables = BooleanField(constraints=[SQL("DEFAULT true")])
    protected_paths = ArrayField(constraints=[SQL("DEFAULT '{/users/password,/users/sign_in,/api/v3/session.json,/api/v3/session,/api/v4/session.json,/api/v4/session,/users,/users/confirmation,/unsubscribes/,/import/github/personal_access_token,/admin/session,/oauth/authorize,/oauth/token}'::character varying[]")], field_class=CharField, null=True)
    pseudonymizer_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    push_event_activities_limit = IntegerField(constraints=[SQL("DEFAULT 3")])
    push_event_hooks_limit = IntegerField(constraints=[SQL("DEFAULT 3")])
    push_rule = ForeignKeyField(column_name='push_rule_id', field='id', model=PushRules, null=True, unique=True)
    raw_blob_request_limit = IntegerField(constraints=[SQL("DEFAULT 300")])
    recaptcha_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    receive_max_input_size = IntegerField(null=True)
    repository_checks_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    repository_size_limit = BigIntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    repository_storages = CharField(constraints=[SQL("DEFAULT 'default'::character varying")], null=True)
    repository_storages_weighted = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    require_admin_approval_after_user_signup = BooleanField(constraints=[SQL("DEFAULT true")])
    require_two_factor_authentication = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    required_instance_ci_template = CharField(null=True)
    restricted_visibility_levels = TextField(null=True)
    rsa_key_restriction = IntegerField(constraints=[SQL("DEFAULT 0")])
    runners_registration_token = CharField(null=True)
    runners_registration_token_encrypted = CharField(null=True)
    seat_link_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    secret_detection_revocation_token_types_url = TextField(null=True)
    secret_detection_token_revocation_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    secret_detection_token_revocation_url = TextField(null=True)
    send_user_confirmation_email = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    session_expire_delay = IntegerField(constraints=[SQL("DEFAULT 10080")])
    shared_runners_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    shared_runners_minutes = IntegerField(constraints=[SQL("DEFAULT 0")])
    shared_runners_text = TextField(null=True)
    shared_runners_text_html = TextField(null=True)
    sign_in_text = TextField(null=True)
    sign_in_text_html = TextField(null=True)
    signup_enabled = BooleanField(null=True)
    slack_app_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    slack_app_id = CharField(null=True)
    snippet_size_limit = BigIntegerField(constraints=[SQL("DEFAULT 52428800")])
    snowplow_app_id = CharField(null=True)
    snowplow_collector_hostname = CharField(null=True)
    snowplow_cookie_domain = CharField(null=True)
    snowplow_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    sourcegraph_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    sourcegraph_public_only = BooleanField(constraints=[SQL("DEFAULT true")])
    sourcegraph_url = CharField(null=True)
    spam_check_endpoint_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    spam_check_endpoint_url = TextField(null=True)
    static_objects_external_storage_auth_token = CharField(null=True)
    static_objects_external_storage_url = CharField(null=True)
    terminal_max_session_time = IntegerField(constraints=[SQL("DEFAULT 0")])
    throttle_authenticated_api_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    throttle_authenticated_api_period_in_seconds = IntegerField(constraints=[SQL("DEFAULT 3600")])
    throttle_authenticated_api_requests_per_period = IntegerField(constraints=[SQL("DEFAULT 7200")])
    throttle_authenticated_web_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    throttle_authenticated_web_period_in_seconds = IntegerField(constraints=[SQL("DEFAULT 3600")])
    throttle_authenticated_web_requests_per_period = IntegerField(constraints=[SQL("DEFAULT 7200")])
    throttle_incident_management_notification_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    throttle_incident_management_notification_per_period = IntegerField(constraints=[SQL("DEFAULT 3600")], null=True)
    throttle_incident_management_notification_period_in_seconds = IntegerField(constraints=[SQL("DEFAULT 3600")], null=True)
    throttle_protected_paths_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    throttle_protected_paths_period_in_seconds = IntegerField(constraints=[SQL("DEFAULT 60")])
    throttle_protected_paths_requests_per_period = IntegerField(constraints=[SQL("DEFAULT 10")])
    throttle_unauthenticated_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    throttle_unauthenticated_period_in_seconds = IntegerField(constraints=[SQL("DEFAULT 3600")])
    throttle_unauthenticated_requests_per_period = IntegerField(constraints=[SQL("DEFAULT 3600")])
    time_tracking_limit_to_hours = BooleanField(constraints=[SQL("DEFAULT false")])
    two_factor_grace_period = IntegerField(constraints=[SQL("DEFAULT 48")], null=True)
    unique_ips_limit_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    unique_ips_limit_per_user = IntegerField(null=True)
    unique_ips_limit_time_window = IntegerField(null=True)
    updated_at = DateTimeField(null=True)
    updating_name_disabled_for_users = BooleanField(constraints=[SQL("DEFAULT false")])
    usage_ping_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    usage_stats_set_by_user = ForeignKeyField(column_name='usage_stats_set_by_user_id', field='id', model=Users, null=True)
    user_default_external = BooleanField(constraints=[SQL("DEFAULT false")])
    user_default_internal_regex = CharField(null=True)
    user_oauth_applications = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    user_show_add_ssh_key_message = BooleanField(constraints=[SQL("DEFAULT true")])
    uuid = CharField(null=True)
    version_check_enabled = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    web_ide_clientside_preview_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    wiki_page_max_content_bytes = BigIntegerField(constraints=[SQL("DEFAULT 52428800")])

    class Meta:
        table_name = 'application_settings'

class ApprovalMergeRequestRules(BaseModel):
    approvals_required = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField(index=True)
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    modified_from_project_rule = BooleanField(constraints=[SQL("DEFAULT false")])
    name = CharField()
    report_type = SmallIntegerField(null=True)
    rule_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    section = TextField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'approval_merge_request_rules'
        indexes = (
            (('merge_request', 'name'), True),
            (('merge_request', 'name', 'section'), True),
            (('merge_request', 'rule_type'), False),
            (('merge_request', 'rule_type'), True),
        )

class ApprovalProjectRules(BaseModel):
    approvals_required = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField()
    id = BigAutoField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    rule_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'approval_project_rules'

class ApprovalMergeRequestRuleSources(BaseModel):
    approval_merge_request_rule = ForeignKeyField(column_name='approval_merge_request_rule_id', field='id', model=ApprovalMergeRequestRules, unique=True)
    approval_project_rule = ForeignKeyField(column_name='approval_project_rule_id', field='id', model=ApprovalProjectRules)
    id = BigAutoField()

    class Meta:
        table_name = 'approval_merge_request_rule_sources'

class ApprovalMergeRequestRulesApprovedApprovers(BaseModel):
    approval_merge_request_rule = ForeignKeyField(column_name='approval_merge_request_rule_id', field='id', model=ApprovalMergeRequestRules)
    id = BigAutoField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'approval_merge_request_rules_approved_approvers'
        indexes = (
            (('approval_merge_request_rule', 'user'), True),
        )

class ApprovalMergeRequestRulesGroups(BaseModel):
    approval_merge_request_rule = ForeignKeyField(column_name='approval_merge_request_rule_id', field='id', model=ApprovalMergeRequestRules)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()

    class Meta:
        table_name = 'approval_merge_request_rules_groups'
        indexes = (
            (('approval_merge_request_rule', 'group'), True),
        )

class ApprovalMergeRequestRulesUsers(BaseModel):
    approval_merge_request_rule = ForeignKeyField(column_name='approval_merge_request_rule_id', field='id', model=ApprovalMergeRequestRules)
    id = BigAutoField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'approval_merge_request_rules_users'
        indexes = (
            (('approval_merge_request_rule', 'user'), True),
        )

class ApprovalProjectRulesGroups(BaseModel):
    approval_project_rule = ForeignKeyField(column_name='approval_project_rule_id', field='id', model=ApprovalProjectRules)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()

    class Meta:
        table_name = 'approval_project_rules_groups'
        indexes = (
            (('approval_project_rule', 'group'), True),
        )

class ProtectedBranches(BaseModel):
    code_owner_approval_required = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField(null=True)
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'protected_branches'
        indexes = (
            (('project', 'code_owner_approval_required'), False),
        )

class ApprovalProjectRulesProtectedBranches(BaseModel):
    approval_project_rule = ForeignKeyField(column_name='approval_project_rule_id', field='id', model=ApprovalProjectRules)
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)

    class Meta:
        table_name = 'approval_project_rules_protected_branches'
        indexes = (
            (('approval_project_rule', 'protected_branch'), True),
        )
        primary_key = CompositeKey('approval_project_rule', 'protected_branch')

class ApprovalProjectRulesUsers(BaseModel):
    approval_project_rule = ForeignKeyField(column_name='approval_project_rule_id', field='id', model=ApprovalProjectRules)
    id = BigAutoField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'approval_project_rules_users'
        indexes = (
            (('approval_project_rule', 'user'), True),
        )

class Approvals(BaseModel):
    created_at = DateTimeField(null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField()

    class Meta:
        table_name = 'approvals'
        indexes = (
            (('user_id', 'merge_request'), True),
        )

class ApproverGroups(BaseModel):
    created_at = DateTimeField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    target_id = IntegerField()
    target_type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'approver_groups'
        indexes = (
            (('target_id', 'target_type'), False),
        )

class Approvers(BaseModel):
    created_at = DateTimeField(null=True)
    target_id = IntegerField()
    target_type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(index=True)

    class Meta:
        table_name = 'approvers'
        indexes = (
            (('target_id', 'target_type'), False),
        )

class ArInternalMetadata(BaseModel):
    created_at = DateTimeField()
    key = CharField(primary_key=True)
    updated_at = DateTimeField()
    value = CharField(null=True)

    class Meta:
        table_name = 'ar_internal_metadata'

class AtlassianIdentities(BaseModel):
    created_at = DateTimeField()
    encrypted_refresh_token = BlobField(null=True)
    encrypted_refresh_token_iv = BlobField(null=True)
    encrypted_token = BlobField(null=True)
    encrypted_token_iv = BlobField(null=True)
    expires_at = DateTimeField(null=True)
    extern_uid = TextField(unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, primary_key=True)

    class Meta:
        table_name = 'atlassian_identities'

class AuditEvents(BaseModel):
    author_id = IntegerField()
    author_name = TextField(null=True)
    created_at = DateTimeField(null=True)
    details = TextField(null=True)
    entity_id = IntegerField()
    entity_path = TextField(null=True)
    entity_type = CharField()
    #ip_address = UnknownField(null=True)  # inet
    target_details = TextField(null=True)
    target_id = BigIntegerField(null=True)
    target_type = TextField(null=True)

    class Meta:
        table_name = 'audit_events'
        indexes = (
            (('created_at', 'author_id'), False),
            (('entity_id', 'entity_type', 'id', 'author_id', 'created_at'), False),
        )

class AuditEventsPart5Fc467Ac26(BaseModel):
    author_id = IntegerField()
    author_name = TextField(null=True)
    created_at = DateTimeField()
    details = TextField(null=True)
    entity_id = IntegerField()
    entity_path = TextField(null=True)
    entity_type = CharField()
    id = BigIntegerField()
    #ip_address = UnknownField(null=True)  # inet
    target_details = TextField(null=True)
    target_id = BigIntegerField(null=True)
    target_type = TextField(null=True)

    class Meta:
        table_name = 'audit_events_part_5fc467ac26'
        primary_key = CompositeKey('created_at', 'id')

class AuthenticationEvents(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    #ip_address = UnknownField(null=True)  # inet
    provider = TextField(index=True)
    result = SmallIntegerField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)
    user_name = TextField()

    class Meta:
        table_name = 'authentication_events'
        indexes = (
            (('provider', 'user', 'created_at'), False),
        )

class AwardEmoji(BaseModel):
    awardable_id = IntegerField(null=True)
    awardable_type = CharField(null=True)
    created_at = DateTimeField(null=True)
    name = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(null=True)

    class Meta:
        table_name = 'award_emoji'
        indexes = (
            (('awardable_type', 'awardable_id'), False),
            (('user_id', 'name'), False),
        )

class AwsRoles(BaseModel):
    created_at = DateTimeField()
    region = TextField(null=True)
    role_arn = CharField(null=True)
    role_external_id = CharField(unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, primary_key=True)

    class Meta:
        table_name = 'aws_roles'

class BackgroundMigrationJobs(BaseModel):
    arguments = BinaryJSONField()
    class_name = TextField()
    created_at = DateTimeField()
    id = BigAutoField()
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'background_migration_jobs'
        indexes = (
            (('class_name', 'arguments'), False),
            (('class_name', 'status', 'id'), False),
        )

class BackupLabels(BaseModel):
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    description_html = TextField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    new_title = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    restore_action = IntegerField(null=True)
    template = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    title = CharField(index=True, null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'backup_labels'
        indexes = (
            (('group', 'project', 'title'), True),
            (('group', 'title'), False),
            (('project', 'title'), False),
            (('type', 'project'), False),
        )

class Badges(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    image_url = CharField()
    link_url = CharField()
    name = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    type = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'badges'

class Boards(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    hide_backlog_list = BooleanField(constraints=[SQL("DEFAULT false")])
    hide_closed_list = BooleanField(constraints=[SQL("DEFAULT false")])
    milestone_id = IntegerField(index=True, null=True)
    name = CharField(constraints=[SQL("DEFAULT 'Development'::character varying")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()
    weight = IntegerField(null=True)

    class Meta:
        table_name = 'boards'

class BoardAssignees(BaseModel):
    assignee = ForeignKeyField(column_name='assignee_id', field='id', model=Users)
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)

    class Meta:
        table_name = 'board_assignees'
        indexes = (
            (('board', 'assignee'), True),
        )

class BoardGroupRecentVisits(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards, null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    id = BigAutoField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'board_group_recent_visits'
        indexes = (
            (('user', 'group', 'board'), True),
        )

class BoardLabels(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels)

    class Meta:
        table_name = 'board_labels'
        indexes = (
            (('board', 'label'), True),
        )

class BoardProjectRecentVisits(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards, null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'board_project_recent_visits'
        indexes = (
            (('user', 'project', 'board'), True),
        )

class BoardUserPreferences(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)
    created_at = DateTimeField()
    hide_labels = BooleanField(null=True)
    id = BigAutoField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'board_user_preferences'
        indexes = (
            (('user', 'board'), True),
        )

class BoardsEpicUserPreferences(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)
    collapsed = BooleanField(constraints=[SQL("DEFAULT false")])
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics)
    id = BigAutoField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'boards_epic_user_preferences'
        indexes = (
            (('board', 'user', 'epic'), True),
        )

class BroadcastMessages(BaseModel):
    broadcast_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    cached_markdown_version = IntegerField(null=True)
    color = CharField(null=True)
    created_at = DateTimeField()
    dismissable = BooleanField(null=True)
    ends_at = DateTimeField()
    font = CharField(null=True)
    message = TextField()
    message_html = TextField()
    starts_at = DateTimeField()
    target_path = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'broadcast_messages'
        indexes = (
            (('ends_at', 'broadcast_type', 'id'), False),
        )

class BulkImports(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    source_type = SmallIntegerField()
    status = SmallIntegerField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'bulk_imports'

class BulkImportConfigurations(BaseModel):
    bulk_import = ForeignKeyField(column_name='bulk_import_id', field='id', model=BulkImports)
    created_at = DateTimeField()
    encrypted_access_token = TextField(null=True)
    encrypted_access_token_iv = TextField(null=True)
    encrypted_url = TextField(null=True)
    encrypted_url_iv = TextField(null=True)
    id = BigAutoField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'bulk_import_configurations'

class BulkImportEntities(BaseModel):
    bulk_import = ForeignKeyField(column_name='bulk_import_id', field='id', model=BulkImports)
    created_at = DateTimeField()
    destination_name = TextField()
    destination_namespace = TextField()
    id = BigAutoField()
    jid = TextField(null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, null=True)
    parent = ForeignKeyField(column_name='parent_id', field='id', model='self', null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    source_full_path = TextField()
    source_type = SmallIntegerField()
    status = SmallIntegerField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'bulk_import_entities'

class BulkImportTrackers(BaseModel):
    bulk_import_entity = ForeignKeyField(column_name='bulk_import_entity_id', field='id', model=BulkImportEntities)
    has_next_page = BooleanField(constraints=[SQL("DEFAULT false")])
    id = BigAutoField()
    next_page = TextField(null=True)
    relation = TextField()

    class Meta:
        table_name = 'bulk_import_trackers'
        indexes = (
            (('bulk_import_entity', 'relation'), True),
        )

class ChatNames(BaseModel):
    chat_id = CharField()
    chat_name = CharField(null=True)
    created_at = DateTimeField()
    last_used_at = DateTimeField(null=True)
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    team_domain = CharField(null=True)
    team_id = CharField()
    updated_at = DateTimeField()
    user_id = IntegerField()

    class Meta:
        table_name = 'chat_names'
        indexes = (
            (('service', 'team_id', 'chat_id'), True),
            (('user_id', 'service'), True),
        )

class ChatTeams(BaseModel):
    created_at = DateTimeField()
    name = CharField(null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, unique=True)
    team_id = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'chat_teams'

class CiResourceGroups(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    key = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_resource_groups'
        indexes = (
            (('project', 'key'), True),
        )

class CiStages(BaseModel):
    created_at = DateTimeField(null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    name = CharField(null=True)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    position = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    status = IntegerField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_stages'
        indexes = (
            (('pipeline'), False),
            (('pipeline', 'name'), True),
        )

class CiBuilds(BaseModel):
    allow_failure = BooleanField(constraints=[SQL("DEFAULT false")])
    artifacts_expire_at = DateTimeField(index=True, null=True)
    artifacts_file = TextField(null=True)
    artifacts_file_store = IntegerField(null=True)
    artifacts_metadata = TextField(null=True)
    artifacts_metadata_store = IntegerField(null=True)
    artifacts_size = BigIntegerField(null=True)
    auto_canceled_by = ForeignKeyField(column_name='auto_canceled_by_id', field='id', model=CiPipelines, null=True)
    commands = TextField(null=True)
    commit = ForeignKeyField(backref='ci_pipelines_commit_set', column_name='commit_id', field='id', model=CiPipelines, null=True)
    coverage = DoubleField(null=True)
    coverage_regex = CharField(null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    environment = CharField(null=True)
    erased_at = DateTimeField(null=True)
    erased_by_id = IntegerField(null=True)
    failure_reason = IntegerField(null=True)
    finished_at = DateTimeField(null=True)
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    name = CharField(null=True)
    options = TextField(null=True)
    processed = BooleanField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    protected = BooleanField(index=True, null=True)
    queued_at = DateTimeField(index=True, null=True)
    ref = CharField(null=True)
    resource_group = ForeignKeyField(column_name='resource_group_id', field='id', model=CiResourceGroups, null=True)
    retried = BooleanField(null=True)
    runner_id = IntegerField(index=True, null=True)
    scheduled_at = DateTimeField(index=True, null=True)
    scheduling_type = SmallIntegerField(null=True)
    stage = CharField(null=True)
    stage_id = ForeignKeyField(column_name='stage_id', field='id', model=CiStages, null=True)
    stage_idx = IntegerField(null=True)
    started_at = DateTimeField(null=True)
    status = CharField(null=True)
    tag = BooleanField(null=True)
    target_url = CharField(null=True)
    token = CharField(null=True, unique=True)
    token_encrypted = CharField(null=True, unique=True)
    trace = TextField(null=True)
    trigger_request_id = IntegerField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    upstream_pipeline = ForeignKeyField(backref='ci_pipelines_upstream_pipeline_set', column_name='upstream_pipeline_id', field='id', model=CiPipelines, null=True)
    user_id = IntegerField(index=True, null=True)
    waiting_for_resource_at = DateTimeField(null=True)
    when = CharField(null=True)
    yaml_variables = TextField(null=True)

    class Meta:
        table_name = 'ci_builds'
        indexes = (
            (('commit', 'artifacts_expire_at', 'id'), False),
            (('commit', 'stage_idx', 'created_at'), False),
            (('commit', 'status', 'type'), False),
            (('commit', 'type', 'name', 'ref'), False),
            (('commit', 'type', 'ref'), False),
            (('name', 'id'), False),
            (('project', 'id'), False),
            (('project', 'name', 'ref'), False),
            (('project', 'status'), False),
            (('resource_group', 'id'), False),
            (('stage_id', 'stage_idx'), False),
            (('status', 'created_at', 'project'), False),
            (('status', 'type', 'runner_id'), False),
            (('user_id', 'created_at'), False),
            (('user_id', 'created_at'), False),
            (('user_id', 'name'), False),
        )

class CiBuildNeeds(BaseModel):
    artifacts = BooleanField(constraints=[SQL("DEFAULT true")])
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    name = TextField()

    class Meta:
        table_name = 'ci_build_needs'
        indexes = (
            (('build', 'name'), True),
        )

class CiBuildPendingStates(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds, unique=True)
    created_at = DateTimeField()
    failure_reason = SmallIntegerField(null=True)
    id = BigAutoField()
    state = SmallIntegerField(null=True)
    trace_checksum = BlobField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_build_pending_states'

class CiBuildReportResults(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds, primary_key=True)
    data = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_build_report_results'

class CiBuildTraceChunks(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    checksum = BlobField(null=True)
    chunk_index = IntegerField()
    data_store = IntegerField()
    id = BigAutoField()
    lock_version = IntegerField(constraints=[SQL("DEFAULT 0")])
    raw_data = BlobField(null=True)

    class Meta:
        table_name = 'ci_build_trace_chunks'
        indexes = (
            (('build', 'chunk_index'), True),
        )

class CiBuildTraceSectionNames(BaseModel):
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_build_trace_section_names'
        indexes = (
            (('project', 'name'), True),
        )

class CiBuildTraceSections(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    byte_end = BigIntegerField()
    byte_start = BigIntegerField()
    date_end = DateTimeField()
    date_start = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    section_name = ForeignKeyField(column_name='section_name_id', field='id', model=CiBuildTraceSectionNames)

    class Meta:
        table_name = 'ci_build_trace_sections'
        indexes = (
            (('build', 'section_name'), True),
        )
        primary_key = CompositeKey('build', 'section_name')

class CiBuildsMetadata(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    config_options = BinaryJSONField(null=True)
    config_variables = BinaryJSONField(null=True)
    environment_auto_stop_in = CharField(null=True)
    expanded_environment_name = CharField(null=True)
    has_exposed_artifacts = BooleanField(null=True)
    interruptible = BooleanField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    secrets = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    timeout = IntegerField(null=True)
    timeout_source = IntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_builds_metadata'

class CiBuildsRunnerSession(BaseModel):
    authorization = CharField(null=True)
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds, unique=True)
    certificate = CharField(null=True)
    id = BigAutoField()
    url = CharField()

    class Meta:
        table_name = 'ci_builds_runner_session'

class CiDailyBuildGroupReportResults(BaseModel):
    data = BinaryJSONField()
    date = DateField()
    default_branch = BooleanField(constraints=[SQL("DEFAULT false")])
    group_name = TextField()
    id = BigAutoField()
    last_pipeline = ForeignKeyField(column_name='last_pipeline_id', field='id', model=CiPipelines)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    ref_path = TextField()

    class Meta:
        table_name = 'ci_daily_build_group_report_results'
        indexes = (
            (('project', 'date'), False),
            (('project', 'ref_path', 'date', 'group_name'), True),
        )

class CiDeletedObjects(BaseModel):
    file = TextField()
    file_store = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    id = BigAutoField()
    pick_up_at = DateTimeField(constraints=[SQL("DEFAULT now()")], index=True)
    store_dir = TextField()

    class Meta:
        table_name = 'ci_deleted_objects'

class CiFreezePeriods(BaseModel):
    created_at = DateTimeField()
    cron_timezone = TextField()
    freeze_end = TextField()
    freeze_start = TextField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_freeze_periods'

class CiGroupVariables(BaseModel):
    created_at = DateTimeField()
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    key = CharField()
    masked = BooleanField(constraints=[SQL("DEFAULT false")])
    protected = BooleanField(constraints=[SQL("DEFAULT false")])
    updated_at = DateTimeField()
    value = TextField(null=True)
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_group_variables'
        indexes = (
            (('group', 'key'), True),
        )

class CiInstanceVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = TextField(null=True)
    id = BigAutoField()
    key = TextField(unique=True)
    masked = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    protected = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_instance_variables'

class CiJobArtifacts(BaseModel):
    created_at = DateTimeField()
    expire_at = DateTimeField(null=True)
    file = CharField(null=True)
    file_format = SmallIntegerField(null=True)
    file_location = SmallIntegerField(null=True)
    file_sha256 = BlobField(null=True)
    file_store = IntegerField(constraints=[SQL("DEFAULT 1")], index=True, null=True)
    file_type = IntegerField()
    job = ForeignKeyField(column_name='job_id', field='id', model=CiBuilds)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    size = BigIntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_job_artifacts'
        indexes = (
            (('expire_at', 'job'), False),
            (('job', 'file_type'), True),
            (('project', 'id'), False),
        )

class CiJobVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    id = BigAutoField()
    job = ForeignKeyField(column_name='job_id', field='id', model=CiBuilds)
    key = CharField()
    source = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_job_variables'
        indexes = (
            (('key', 'job'), True),
        )

class CiPipelineArtifacts(BaseModel):
    created_at = DateTimeField()
    expire_at = DateTimeField(index=True, null=True)
    file = TextField(null=True)
    file_format = SmallIntegerField()
    file_store = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    file_type = SmallIntegerField()
    id = BigAutoField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    size = IntegerField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_pipeline_artifacts'
        indexes = (
            (('pipeline', 'file_type'), True),
        )

class CiPipelineChatData(BaseModel):
    chat_name = ForeignKeyField(column_name='chat_name_id', field='id', model=ChatNames)
    id = BigAutoField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, unique=True)
    response_url = TextField()

    class Meta:
        table_name = 'ci_pipeline_chat_data'

class CiPipelineMessages(BaseModel):
    content = TextField()
    id = BigAutoField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    severity = SmallIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'ci_pipeline_messages'

class CiPipelineScheduleVariables(BaseModel):
    created_at = DateTimeField(null=True)
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline_schedule = ForeignKeyField(column_name='pipeline_schedule_id', field='id', model=CiPipelineSchedules)
    updated_at = DateTimeField(null=True)
    value = TextField(null=True)
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_pipeline_schedule_variables'
        indexes = (
            (('pipeline_schedule', 'key'), True),
        )

class CiPipelineVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    key = CharField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    value = TextField(null=True)
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_pipeline_variables'
        indexes = (
            (('pipeline', 'key'), True),
        )

class CiPipelinesConfig(BaseModel):
    content = TextField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, primary_key=True)

    class Meta:
        table_name = 'ci_pipelines_config'

class CiPlatformMetrics(BaseModel):
    count = IntegerField()
    id = BigAutoField()
    platform_target = TextField()
    recorded_at = DateTimeField()

    class Meta:
        table_name = 'ci_platform_metrics'

class CiResources(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds, null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    resource_group = ForeignKeyField(column_name='resource_group_id', field='id', model=CiResourceGroups)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'ci_resources'
        indexes = (
            (('resource_group', 'build'), True),
        )

class CiRunners(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 0")])
    active = BooleanField(constraints=[SQL("DEFAULT true")])
    architecture = CharField(null=True)
    contacted_at = DateTimeField(index=True, null=True)
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    ip_address = CharField(null=True)
    is_shared = BooleanField(constraints=[SQL("DEFAULT false")], index=True, null=True)
    locked = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    maximum_timeout = IntegerField(null=True)
    name = CharField(null=True)
    platform = CharField(null=True)
    private_projects_minutes_cost_factor = DoubleField(constraints=[SQL("DEFAULT 1.0")])
    public_projects_minutes_cost_factor = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    revision = CharField(null=True)
    run_untagged = BooleanField(constraints=[SQL("DEFAULT true")])
    runner_type = SmallIntegerField(index=True)
    token = CharField(index=True, null=True)
    token_encrypted = CharField(index=True, null=True)
    updated_at = DateTimeField(null=True)
    version = CharField(null=True)

    class Meta:
        table_name = 'ci_runners'

class CiRunnerNamespaces(BaseModel):
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, null=True)
    runner = ForeignKeyField(column_name='runner_id', field='id', model=CiRunners, null=True)

    class Meta:
        table_name = 'ci_runner_namespaces'
        indexes = (
            (('runner', 'namespace'), True),
        )

class CiRunnerProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    runner_id = IntegerField(index=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_runner_projects'

class CiSourcesPipelines(BaseModel):
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    source_job = ForeignKeyField(column_name='source_job_id', field='id', model=CiBuilds, null=True)
    source_pipeline = ForeignKeyField(backref='ci_pipelines_source_pipeline_set', column_name='source_pipeline_id', field='id', model=CiPipelines, null=True)
    source_project = ForeignKeyField(backref='projects_source_project_set', column_name='source_project_id', field='id', model=Projects, null=True)

    class Meta:
        table_name = 'ci_sources_pipelines'

class CiSourcesProjects(BaseModel):
    id = BigAutoField()
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    source_project = ForeignKeyField(column_name='source_project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_sources_projects'
        indexes = (
            (('source_project', 'pipeline'), True),
        )

class CiSubscriptionsProjects(BaseModel):
    downstream_project = ForeignKeyField(column_name='downstream_project_id', field='id', model=Projects)
    id = BigAutoField()
    upstream_project = ForeignKeyField(backref='projects_upstream_project_set', column_name='upstream_project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_subscriptions_projects'
        indexes = (
            (('downstream_project', 'upstream_project'), True),
        )

class CiTestCases(BaseModel):
    id = BigAutoField()
    key_hash = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'ci_test_cases'
        indexes = (
            (('project', 'key_hash'), True),
        )

class CiTestCaseFailures(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    failed_at = DateTimeField(null=True)
    id = BigAutoField()
    test_case = ForeignKeyField(column_name='test_case_id', field='id', model=CiTestCases)

    class Meta:
        table_name = 'ci_test_case_failures'
        indexes = (
            (('test_case', 'failed_at', 'build'), True),
        )

class CiTriggers(BaseModel):
    created_at = DateTimeField(null=True)
    description = CharField(null=True)
    owner = ForeignKeyField(column_name='owner_id', field='id', model=Users)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    ref = CharField(null=True)
    token = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ci_triggers'

class CiTriggerRequests(BaseModel):
    commit_id = IntegerField(index=True, null=True)
    created_at = DateTimeField(null=True)
    trigger = ForeignKeyField(column_name='trigger_id', field='id', model=CiTriggers)
    updated_at = DateTimeField(null=True)
    variables = TextField(null=True)

    class Meta:
        table_name = 'ci_trigger_requests'
        indexes = (
            (('trigger', 'id'), False),
        )

class CiVariables(BaseModel):
    encrypted_value = TextField(null=True)
    encrypted_value_iv = CharField(null=True)
    encrypted_value_salt = CharField(null=True)
    environment_scope = CharField(constraints=[SQL("DEFAULT '*'::character varying")])
    key = CharField(index=True)
    masked = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    protected = BooleanField(constraints=[SQL("DEFAULT false")])
    value = TextField(null=True)
    variable_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'ci_variables'
        indexes = (
            (('project', 'key', 'environment_scope'), True),
        )

class ClusterAgents(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    name = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'cluster_agents'
        indexes = (
            (('project', 'name'), True),
        )

class ClusterAgentTokens(BaseModel):
    agent = ForeignKeyField(column_name='agent_id', field='id', model=ClusterAgents)
    created_at = DateTimeField()
    id = BigAutoField()
    token_encrypted = TextField(unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'cluster_agent_tokens'

class Clusters(BaseModel):
    cleanup_status = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    cleanup_status_reason = TextField(null=True)
    cluster_type = SmallIntegerField(constraints=[SQL("DEFAULT 3")])
    created_at = DateTimeField()
    domain = CharField(null=True)
    enabled = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    environment_scope = CharField(constraints=[SQL("DEFAULT '*'::character varying")])
    helm_major_version = IntegerField(constraints=[SQL("DEFAULT 2")])
    managed = BooleanField(constraints=[SQL("DEFAULT true")])
    management_project = ForeignKeyField(column_name='management_project_id', field='id', model=Projects, null=True)
    name = CharField()
    namespace_per_environment = BooleanField(constraints=[SQL("DEFAULT true")])
    platform_type = IntegerField(null=True)
    provider_type = IntegerField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'clusters'
        indexes = (
            (('enabled', 'cluster_type', 'id', 'created_at'), False),
            (('enabled', 'provider_type', 'id'), False),
        )

class ClusterGroups(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)

    class Meta:
        table_name = 'cluster_groups'
        indexes = (
            (('cluster', 'group'), True),
        )

class ClusterPlatformsKubernetes(BaseModel):
    api_url = TextField(null=True)
    authorization_type = SmallIntegerField(null=True)
    ca_cert = TextField(null=True)
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_password = TextField(null=True)
    encrypted_password_iv = CharField(null=True)
    encrypted_token = TextField(null=True)
    encrypted_token_iv = CharField(null=True)
    namespace = CharField(null=True)
    updated_at = DateTimeField()
    username = CharField(null=True)

    class Meta:
        table_name = 'cluster_platforms_kubernetes'

class ClusterProjects(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'cluster_projects'

class ClusterProvidersAws(BaseModel):
    access_key_id = CharField(null=True)
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_secret_access_key = TextField(null=True)
    encrypted_secret_access_key_iv = CharField(null=True)
    id = BigAutoField()
    instance_type = CharField()
    key_name = CharField()
    kubernetes_version = TextField(constraints=[SQL("DEFAULT '1.14'::text")])
    num_nodes = IntegerField()
    region = CharField()
    role_arn = CharField()
    security_group_id = CharField()
    session_token = TextField(null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    subnet_ids = ArrayField(constraints=[SQL("DEFAULT '{}'::character varying[]")], field_class=CharField)
    updated_at = DateTimeField()
    vpc_id = CharField()

    class Meta:
        table_name = 'cluster_providers_aws'
        indexes = (
            (('cluster', 'status'), False),
        )

class ClusterProvidersGcp(BaseModel):
    cloud_run = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_access_token = TextField(null=True)
    encrypted_access_token_iv = CharField(null=True)
    endpoint = CharField(null=True)
    gcp_project_id = CharField()
    legacy_abac = BooleanField(constraints=[SQL("DEFAULT false")])
    machine_type = CharField(null=True)
    num_nodes = IntegerField()
    operation_id = CharField(null=True)
    status = IntegerField(null=True)
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    zone = CharField()

    class Meta:
        table_name = 'cluster_providers_gcp'

class ClustersApplicationsCertManagers(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    email = CharField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_cert_managers'

class ClustersApplicationsCilium(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    id = BigAutoField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'clusters_applications_cilium'

class ClustersApplicationsCrossplane(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    id = BigAutoField()
    stack = CharField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_crossplane'

class ClustersApplicationsElasticStacks(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    id = BigAutoField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_elastic_stacks'

class ClustersApplicationsFluentd(BaseModel):
    cilium_log_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    host = CharField()
    id = BigAutoField()
    port = IntegerField()
    protocol = SmallIntegerField()
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()
    waf_log_enabled = BooleanField(constraints=[SQL("DEFAULT true")])

    class Meta:
        table_name = 'clusters_applications_fluentd'

class ClustersApplicationsHelm(BaseModel):
    ca_cert = TextField(null=True)
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_ca_key = TextField(null=True)
    encrypted_ca_key_iv = TextField(null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_helm'

class ClustersApplicationsIngress(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    cluster_ip = CharField(null=True)
    created_at = DateTimeField()
    external_hostname = CharField(null=True)
    external_ip = CharField(null=True)
    ingress_type = IntegerField()
    modsecurity_enabled = BooleanField(null=True)
    modsecurity_mode = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_ingress'
        indexes = (
            (('modsecurity_enabled', 'modsecurity_mode', 'cluster'), False),
        )

class OauthApplications(BaseModel):
    confidential = BooleanField(constraints=[SQL("DEFAULT true")])
    created_at = DateTimeField(null=True)
    name = CharField()
    owner_id = IntegerField(null=True)
    owner_type = CharField(null=True)
    redirect_uri = TextField()
    scopes = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    secret = CharField()
    trusted = BooleanField(constraints=[SQL("DEFAULT false")])
    uid = CharField(unique=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'oauth_applications'
        indexes = (
            (('owner_id', 'owner_type'), False),
        )

class ClustersApplicationsJupyter(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    hostname = CharField(null=True)
    oauth_application = ForeignKeyField(column_name='oauth_application_id', field='id', model=OauthApplications, null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_jupyter'

class ClustersApplicationsKnative(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    external_hostname = CharField(null=True)
    external_ip = CharField(null=True)
    hostname = CharField(null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_knative'

class ClustersApplicationsPrometheus(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    encrypted_alert_manager_token = CharField(null=True)
    encrypted_alert_manager_token_iv = CharField(null=True)
    healthy = BooleanField(null=True)
    last_update_started_at = DateTimeField(null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_prometheus'

class ClustersApplicationsRunners(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, unique=True)
    created_at = DateTimeField()
    privileged = BooleanField(constraints=[SQL("DEFAULT true")])
    runner = ForeignKeyField(column_name='runner_id', field='id', model=CiRunners, null=True)
    status = IntegerField()
    status_reason = TextField(null=True)
    updated_at = DateTimeField()
    version = CharField()

    class Meta:
        table_name = 'clusters_applications_runners'

class ClustersKubernetesNamespaces(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    cluster_project = ForeignKeyField(column_name='cluster_project_id', field='id', model=ClusterProjects, null=True)
    created_at = DateTimeField()
    encrypted_service_account_token = TextField(null=True)
    encrypted_service_account_token_iv = CharField(null=True)
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments, null=True)
    id = BigAutoField()
    namespace = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    service_account_name = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'clusters_kubernetes_namespaces'
        indexes = (
            (('cluster', 'namespace'), True),
            (('cluster', 'project', 'environment'), True),
        )

class CommitUserMentions(BaseModel):
    commit_id = CharField()
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, unique=True)

    class Meta:
        table_name = 'commit_user_mentions'
        indexes = (
            (('commit_id', 'note'), False),
        )

class ComplianceManagementFrameworks(BaseModel):
    color = TextField()
    description = TextField()
    group_id = BigIntegerField(null=True)
    id = BigAutoField()
    name = TextField()
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)

    class Meta:
        table_name = 'compliance_management_frameworks'
        indexes = (
            (('namespace', 'name'), True),
        )

class ContainerExpirationPolicies(BaseModel):
    cadence = CharField(constraints=[SQL("DEFAULT '1d'::character varying")])
    created_at = DateTimeField()
    enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    keep_n = IntegerField(constraints=[SQL("DEFAULT 10")], null=True)
    name_regex = CharField(constraints=[SQL("DEFAULT '.*'::character varying")], null=True)
    name_regex_keep = TextField(null=True)
    next_run_at = DateTimeField(null=True)
    older_than = CharField(constraints=[SQL("DEFAULT '90d'::character varying")], null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'container_expiration_policies'
        indexes = (
            (('next_run_at', 'enabled'), False),
            (('project', 'next_run_at', 'enabled'), False),
        )

class ContainerRepositories(BaseModel):
    created_at = DateTimeField()
    expiration_policy_cleanup_status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    expiration_policy_started_at = DateTimeField(null=True)
    name = CharField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    status = SmallIntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'container_repositories'
        indexes = (
            (('expiration_policy_cleanup_status', 'expiration_policy_started_at'), False),
            (('project', 'id'), False),
            (('project', 'name'), True),
        )

class ConversationalDevelopmentIndexMetrics(BaseModel):
    created_at = DateTimeField()
    instance_boards = DoubleField()
    instance_ci_pipelines = DoubleField()
    instance_deployments = DoubleField()
    instance_environments = DoubleField()
    instance_issues = DoubleField()
    instance_merge_requests = DoubleField()
    instance_milestones = DoubleField()
    instance_notes = DoubleField()
    instance_projects_prometheus_active = DoubleField()
    instance_service_desk_issues = DoubleField()
    leader_boards = DoubleField()
    leader_ci_pipelines = DoubleField()
    leader_deployments = DoubleField()
    leader_environments = DoubleField()
    leader_issues = DoubleField()
    leader_merge_requests = DoubleField()
    leader_milestones = DoubleField()
    leader_notes = DoubleField()
    leader_projects_prometheus_active = DoubleField()
    leader_service_desk_issues = DoubleField()
    percentage_boards = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_ci_pipelines = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_deployments = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_environments = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_issues = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_merge_requests = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_milestones = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_notes = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_projects_prometheus_active = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    percentage_service_desk_issues = DoubleField(constraints=[SQL("DEFAULT 0.0")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'conversational_development_index_metrics'

class CsvIssueImports(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'csv_issue_imports'

class CustomEmoji(BaseModel):
    created_at = DateTimeField()
    external = BooleanField(constraints=[SQL("DEFAULT true")])
    file = TextField()
    id = BigAutoField()
    name = TextField()
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'custom_emoji'
        indexes = (
            (('namespace', 'name'), True),
        )

class DastScannerProfiles(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    name = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    scan_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    show_debug_messages = BooleanField(constraints=[SQL("DEFAULT false")])
    spider_timeout = SmallIntegerField(null=True)
    target_timeout = SmallIntegerField(null=True)
    updated_at = DateTimeField()
    use_ajax_spider = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'dast_scanner_profiles'
        indexes = (
            (('project', 'name'), True),
        )

class DastSiteTokens(BaseModel):
    created_at = DateTimeField()
    expired_at = DateTimeField(null=True)
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    token = TextField()
    updated_at = DateTimeField()
    url = TextField()

    class Meta:
        table_name = 'dast_site_tokens'

class DastSiteValidations(BaseModel):
    created_at = DateTimeField()
    dast_site_token = ForeignKeyField(column_name='dast_site_token_id', field='id', model=DastSiteTokens)
    id = BigAutoField()
    state = TextField(constraints=[SQL("DEFAULT 'pending'::text")])
    updated_at = DateTimeField()
    url_base = TextField()
    url_path = TextField()
    validation_failed_at = DateTimeField(null=True)
    validation_last_retried_at = DateTimeField(null=True)
    validation_passed_at = DateTimeField(null=True)
    validation_started_at = DateTimeField(null=True)
    validation_strategy = SmallIntegerField()

    class Meta:
        table_name = 'dast_site_validations'
        indexes = (
            (('url_base', 'state'), False),
        )

class DastSites(BaseModel):
    created_at = DateTimeField()
    dast_site_validation = ForeignKeyField(column_name='dast_site_validation_id', field='id', model=DastSiteValidations, null=True)
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    url = TextField()

    class Meta:
        table_name = 'dast_sites'
        indexes = (
            (('project', 'url'), True),
        )

class DastSiteProfiles(BaseModel):
    created_at = DateTimeField()
    dast_site = ForeignKeyField(column_name='dast_site_id', field='id', model=DastSites)
    id = BigAutoField()
    name = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'dast_site_profiles'
        indexes = (
            (('project', 'name'), True),
        )

class DependencyProxyBlobs(BaseModel):
    created_at = DateTimeField()
    file = TextField()
    file_name = CharField()
    file_store = IntegerField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    size = BigIntegerField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'dependency_proxy_blobs'
        indexes = (
            (('group', 'file_name'), False),
        )

class DependencyProxyGroupSettings(BaseModel):
    created_at = DateTimeField()
    enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'dependency_proxy_group_settings'

class DeployKeysProjects(BaseModel):
    can_push = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField(null=True)
    deploy_key_id = IntegerField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'deploy_keys_projects'

class DeployTokens(BaseModel):
    created_at = DateTimeField()
    deploy_token_type = SmallIntegerField(constraints=[SQL("DEFAULT 2")])
    expires_at = DateTimeField()
    name = CharField()
    read_package_registry = BooleanField(constraints=[SQL("DEFAULT false")])
    read_registry = BooleanField(constraints=[SQL("DEFAULT false")])
    read_repository = BooleanField(constraints=[SQL("DEFAULT false")])
    revoked = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    token = CharField(null=True, unique=True)
    token_encrypted = CharField(null=True, unique=True)
    username = CharField(null=True)
    write_package_registry = BooleanField(constraints=[SQL("DEFAULT false")])
    write_registry = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'deploy_tokens'
        indexes = (
            (('token', 'expires_at', 'id'), False),
        )

class Deployments(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, null=True)
    created_at = DateTimeField(index=True, null=True)
    deployable_id = IntegerField(null=True)
    deployable_type = CharField(null=True)
    environment_id = IntegerField()
    finished_at = DateTimeField(null=True)
    iid = IntegerField()
    on_stop = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    ref = CharField()
    sha = CharField()
    status = SmallIntegerField()
    tag = BooleanField()
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(null=True)

    class Meta:
        table_name = 'deployments'
        indexes = (
            (('cluster', 'environment_id'), False),
            (('cluster', 'status'), False),
            (('deployable_type', 'deployable_id'), False),
            (('environment_id', 'id'), False),
            (('environment_id', 'iid', 'project'), False),
            (('environment_id', 'status'), False),
            (('id', 'status', 'created_at'), False),
            (('project', 'id'), False),
            (('project', 'iid'), True),
            (('project', 'ref'), False),
            (('project', 'sha'), False),
            (('project', 'status'), False),
            (('project', 'status', 'created_at'), False),
            (('project', 'updated_at', 'id'), False),
            (('user_id', 'status', 'created_at'), False),
        )

class DeploymentClusters(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters)
    deployment = ForeignKeyField(column_name='deployment_id', field='id', model=Deployments, primary_key=True)
    kubernetes_namespace = CharField(null=True)

    class Meta:
        table_name = 'deployment_clusters'
        indexes = (
            (('cluster', 'deployment'), True),
            (('cluster', 'kubernetes_namespace'), False),
        )

class DeploymentMergeRequests(BaseModel):
    deployment = ForeignKeyField(column_name='deployment_id', field='id', model=Deployments)
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)

    class Meta:
        table_name = 'deployment_merge_requests'
        indexes = (
            (('deployment', 'merge_request'), True),
            (('environment', 'merge_request'), True),
        )
        primary_key = CompositeKey('deployment', 'merge_request')

class DescriptionVersions(BaseModel):
    created_at = DateTimeField()
    deleted_at = DateTimeField(null=True)
    description = TextField(null=True)
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics, null=True)
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'description_versions'

class DesignManagementDesigns(BaseModel):
    filename = CharField()
    id = BigAutoField()
    iid = IntegerField(null=True)
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    relative_position = IntegerField(null=True)

    class Meta:
        table_name = 'design_management_designs'
        indexes = (
            (('issue', 'filename'), True),
            (('issue', 'relative_position', 'id'), False),
            (('project', 'iid'), True),
        )

class DesignManagementVersions(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    sha = BlobField()

    class Meta:
        table_name = 'design_management_versions'
        indexes = (
            (('sha', 'issue'), True),
        )

class DesignManagementDesignsVersions(BaseModel):
    design = ForeignKeyField(column_name='design_id', field='id', model=DesignManagementDesigns)
    event = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    id = BigAutoField()
    image_v432x230 = CharField(null=True)
    version = ForeignKeyField(column_name='version_id', field='id', model=DesignManagementVersions)

    class Meta:
        table_name = 'design_management_designs_versions'
        indexes = (
            (('design', 'version'), True),
        )

class DesignUserMentions(BaseModel):
    design = ForeignKeyField(column_name='design_id', field='id', model=DesignManagementDesigns)
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, unique=True)

    class Meta:
        table_name = 'design_user_mentions'
        indexes = (
            (('design', 'note'), False),
        )

class DiffNotePositions(BaseModel):
    base_sha = BlobField()
    diff_content_type = SmallIntegerField()
    diff_type = SmallIntegerField()
    head_sha = BlobField()
    id = BigAutoField()
    line_code = CharField()
    new_line = IntegerField(null=True)
    new_path = TextField()
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes)
    old_line = IntegerField(null=True)
    old_path = TextField()
    start_sha = BlobField()

    class Meta:
        table_name = 'diff_note_positions'
        indexes = (
            (('note', 'diff_type'), True),
        )

class DraftNotes(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    change_position = TextField(null=True)
    commit_id = BlobField(null=True)
    discussion_id = CharField(index=True, null=True)
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    note = TextField()
    original_position = TextField(null=True)
    position = TextField(null=True)
    resolve_discussion = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'draft_notes'

class ElasticReindexingTasks(BaseModel):
    created_at = DateTimeField()
    delete_original_index_at = DateTimeField(null=True)
    documents_count = IntegerField(null=True)
    documents_count_target = IntegerField(null=True)
    elastic_task = TextField(null=True)
    error_message = TextField(null=True)
    id = BigAutoField()
    in_progress = BooleanField(constraints=[SQL("DEFAULT true")], unique=True)
    index_name_from = TextField(null=True)
    index_name_to = TextField(null=True)
    state = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'elastic_reindexing_tasks'

class ElasticsearchIndexedNamespaces(BaseModel):
    created_at = DateTimeField(index=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, null=True, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'elasticsearch_indexed_namespaces'
        primary_key = False

class ElasticsearchIndexedProjects(BaseModel):
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'elasticsearch_indexed_projects'
        primary_key = False

class Emails(BaseModel):
    confirmation_sent_at = DateTimeField(null=True)
    confirmation_token = CharField(null=True, unique=True)
    confirmed_at = DateTimeField(null=True)
    created_at = DateTimeField(null=True)
    email = CharField(unique=True)
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'emails'

class EpicIssues(BaseModel):
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics)
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)
    relative_position = IntegerField(null=True)

    class Meta:
        table_name = 'epic_issues'

class EpicMetrics(BaseModel):
    created_at = DateTimeField()
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'epic_metrics'

class EpicUserMentions(BaseModel):
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics, unique=True)
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)

    class Meta:
        table_name = 'epic_user_mentions'
        indexes = (
            (('epic', 'note'), True),
        )

class Events(BaseModel):
    action = SmallIntegerField(index=True)
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    created_at = DateTimeField()
    fingerprint = BlobField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    target_id = IntegerField(null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'events'
        indexes = (
            (('author', 'created_at'), False),
            (('author', 'created_at'), False),
            (('author', 'created_at'), False),
            (('author', 'project'), False),
            (('author', 'project'), False),
            (('created_at', 'author'), False),
            (('created_at', 'author'), False),
            (('project', 'created_at'), False),
            (('project', 'created_at'), False),
            (('project', 'id'), False),
            (('project', 'id'), False),
            (('project', 'id'), False),
            (('target_type', 'target_id'), False),
            (('target_type', 'target_id'), False),
            (('target_type', 'target_id', 'fingerprint'), True),
            (('target_type', 'target_id', 'fingerprint'), True),
        )

class Releases(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    description = TextField(null=True)
    description_html = TextField(null=True)
    name = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    released_at = DateTimeField()
    sha = CharField(null=True)
    tag = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'releases'
        indexes = (
            (('project', 'tag'), False),
        )

class Evidences(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    release = ForeignKeyField(column_name='release_id', field='id', model=Releases)
    summary = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    summary_sha = BlobField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'evidences'

class Experiments(BaseModel):
    id = BigAutoField()
    name = TextField(unique=True)

    class Meta:
        table_name = 'experiments'

class ExperimentUsers(BaseModel):
    created_at = DateTimeField()
    experiment = ForeignKeyField(column_name='experiment_id', field='id', model=Experiments)
    group_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    id = BigAutoField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'experiment_users'

class FeatureGates(BaseModel):
    created_at = DateTimeField()
    feature_key = CharField()
    key = CharField()
    updated_at = DateTimeField()
    value = CharField(null=True)

    class Meta:
        table_name = 'feature_gates'
        indexes = (
            (('feature_key', 'key', 'value'), True),
        )

class Features(BaseModel):
    created_at = DateTimeField()
    key = CharField(unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'features'

class ForkNetworks(BaseModel):
    deleted_root_project_name = CharField(null=True)
    root_project = ForeignKeyField(column_name='root_project_id', field='id', model=Projects, null=True, unique=True)

    class Meta:
        table_name = 'fork_networks'

class ForkNetworkMembers(BaseModel):
    fork_network = ForeignKeyField(column_name='fork_network_id', field='id', model=ForkNetworks)
    forked_from_project = ForeignKeyField(column_name='forked_from_project_id', field='id', model=Projects, null=True)
    project = ForeignKeyField(backref='projects_project_set', column_name='project_id', field='id', model=Projects, unique=True)

    class Meta:
        table_name = 'fork_network_members'

class GeoCacheInvalidationEvents(BaseModel):
    id = BigAutoField()
    key = CharField()

    class Meta:
        table_name = 'geo_cache_invalidation_events'

class GeoContainerRepositoryUpdatedEvents(BaseModel):
    container_repository = ForeignKeyField(column_name='container_repository_id', field='id', model=ContainerRepositories)
    id = BigAutoField()

    class Meta:
        table_name = 'geo_container_repository_updated_events'

class GeoEvents(BaseModel):
    created_at = DateTimeField()
    event_name = CharField()
    id = BigAutoField()
    payload = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    replicable_name = CharField()

    class Meta:
        table_name = 'geo_events'

class GeoHashedStorageMigratedEvents(BaseModel):
    id = BigAutoField()
    new_design_disk_path = TextField(null=True)
    new_disk_path = TextField()
    new_storage_version = SmallIntegerField()
    new_wiki_disk_path = TextField()
    old_design_disk_path = TextField(null=True)
    old_disk_path = TextField()
    old_storage_version = SmallIntegerField(null=True)
    old_wiki_disk_path = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    repository_storage_name = TextField()

    class Meta:
        table_name = 'geo_hashed_storage_migrated_events'

class GeoJobArtifactDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigAutoField()
    job_artifact_id = IntegerField(index=True)

    class Meta:
        table_name = 'geo_job_artifact_deleted_events'

class GeoLfsObjectDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigAutoField()
    lfs_object_id = IntegerField(index=True)
    oid = CharField()

    class Meta:
        table_name = 'geo_lfs_object_deleted_events'

class GeoNodes(BaseModel):
    access_key = CharField(index=True, null=True)
    clone_url_prefix = CharField(null=True)
    container_repositories_max_capacity = IntegerField(constraints=[SQL("DEFAULT 10")])
    created_at = DateTimeField(null=True)
    enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    encrypted_secret_access_key = CharField(null=True)
    encrypted_secret_access_key_iv = CharField(null=True)
    files_max_capacity = IntegerField(constraints=[SQL("DEFAULT 10")])
    internal_url = CharField(null=True)
    minimum_reverification_interval = IntegerField(constraints=[SQL("DEFAULT 7")])
    name = CharField(unique=True)
    oauth_application_id = IntegerField(null=True)
    primary = BooleanField(constraints=[SQL("DEFAULT false")])
    repos_max_capacity = IntegerField(constraints=[SQL("DEFAULT 25")])
    selective_sync_shards = TextField(null=True)
    selective_sync_type = CharField(null=True)
    sync_object_storage = BooleanField(constraints=[SQL("DEFAULT false")])
    updated_at = DateTimeField(null=True)
    url = CharField()
    verification_max_capacity = IntegerField(constraints=[SQL("DEFAULT 100")])

    class Meta:
        table_name = 'geo_nodes'

class GeoRepositoriesChangedEvents(BaseModel):
    geo_node = ForeignKeyField(column_name='geo_node_id', field='id', model=GeoNodes)
    id = BigAutoField()

    class Meta:
        table_name = 'geo_repositories_changed_events'

class GeoRepositoryCreatedEvents(BaseModel):
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    project_name = TextField()
    repo_path = TextField()
    repository_storage_name = TextField()
    wiki_path = TextField(null=True)

    class Meta:
        table_name = 'geo_repository_created_events'

class GeoRepositoryDeletedEvents(BaseModel):
    deleted_path = TextField()
    deleted_project_name = TextField()
    deleted_wiki_path = TextField(null=True)
    id = BigAutoField()
    project_id = IntegerField(index=True)
    repository_storage_name = TextField()

    class Meta:
        table_name = 'geo_repository_deleted_events'

class GeoRepositoryRenamedEvents(BaseModel):
    id = BigAutoField()
    new_path = TextField()
    new_path_with_namespace = TextField()
    new_wiki_path_with_namespace = TextField()
    old_path = TextField()
    old_path_with_namespace = TextField()
    old_wiki_path_with_namespace = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    repository_storage_name = TextField()

    class Meta:
        table_name = 'geo_repository_renamed_events'

class GeoRepositoryUpdatedEvents(BaseModel):
    branches_affected = IntegerField()
    id = BigAutoField()
    new_branch = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    ref = TextField(null=True)
    remove_branch = BooleanField(constraints=[SQL("DEFAULT false")])
    source = SmallIntegerField(index=True)
    tags_affected = IntegerField()

    class Meta:
        table_name = 'geo_repository_updated_events'

class GeoResetChecksumEvents(BaseModel):
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'geo_reset_checksum_events'

class GeoUploadDeletedEvents(BaseModel):
    file_path = CharField()
    id = BigAutoField()
    model_id = IntegerField()
    model_type = CharField()
    upload_id = IntegerField(index=True)
    uploader = CharField()

    class Meta:
        table_name = 'geo_upload_deleted_events'

class GeoEventLog(BaseModel):
    cache_invalidation_event = ForeignKeyField(column_name='cache_invalidation_event_id', field='id', model=GeoCacheInvalidationEvents, null=True)
    container_repository_updated_event = ForeignKeyField(column_name='container_repository_updated_event_id', field='id', model=GeoContainerRepositoryUpdatedEvents, null=True)
    created_at = DateTimeField()
    geo_event = ForeignKeyField(column_name='geo_event_id', field='id', model=GeoEvents, null=True)
    hashed_storage_attachments_event_id = BigIntegerField(index=True, null=True)
    hashed_storage_migrated_event = ForeignKeyField(column_name='hashed_storage_migrated_event_id', field='id', model=GeoHashedStorageMigratedEvents, null=True)
    id = BigAutoField()
    job_artifact_deleted_event = ForeignKeyField(column_name='job_artifact_deleted_event_id', field='id', model=GeoJobArtifactDeletedEvents, null=True)
    lfs_object_deleted_event = ForeignKeyField(column_name='lfs_object_deleted_event_id', field='id', model=GeoLfsObjectDeletedEvents, null=True)
    repositories_changed_event = ForeignKeyField(column_name='repositories_changed_event_id', field='id', model=GeoRepositoriesChangedEvents, null=True)
    repository_created_event = ForeignKeyField(column_name='repository_created_event_id', field='id', model=GeoRepositoryCreatedEvents, null=True)
    repository_deleted_event = ForeignKeyField(column_name='repository_deleted_event_id', field='id', model=GeoRepositoryDeletedEvents, null=True)
    repository_renamed_event = ForeignKeyField(column_name='repository_renamed_event_id', field='id', model=GeoRepositoryRenamedEvents, null=True)
    repository_updated_event = ForeignKeyField(column_name='repository_updated_event_id', field='id', model=GeoRepositoryUpdatedEvents, null=True)
    reset_checksum_event = ForeignKeyField(column_name='reset_checksum_event_id', field='id', model=GeoResetChecksumEvents, null=True)
    upload_deleted_event = ForeignKeyField(column_name='upload_deleted_event_id', field='id', model=GeoUploadDeletedEvents, null=True)

    class Meta:
        table_name = 'geo_event_log'

class GeoHashedStorageAttachmentsEvents(BaseModel):
    id = BigAutoField()
    new_attachments_path = TextField()
    old_attachments_path = TextField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'geo_hashed_storage_attachments_events'

class GeoNodeNamespaceLinks(BaseModel):
    created_at = DateTimeField()
    geo_node = ForeignKeyField(column_name='geo_node_id', field='id', model=GeoNodes)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'geo_node_namespace_links'
        indexes = (
            (('geo_node', 'namespace'), True),
        )

class GeoNodeStatuses(BaseModel):
    attachments_count = IntegerField(null=True)
    attachments_failed_count = IntegerField(null=True)
    attachments_synced_count = IntegerField(null=True)
    attachments_synced_missing_on_primary_count = IntegerField(null=True)
    container_repositories_count = IntegerField(null=True)
    container_repositories_failed_count = IntegerField(null=True)
    container_repositories_registry_count = IntegerField(null=True)
    container_repositories_synced_count = IntegerField(null=True)
    created_at = DateTimeField()
    cursor_last_event_date = DateTimeField(null=True)
    cursor_last_event_id = IntegerField(null=True)
    db_replication_lag_seconds = IntegerField(null=True)
    design_repositories_count = IntegerField(null=True)
    design_repositories_failed_count = IntegerField(null=True)
    design_repositories_registry_count = IntegerField(null=True)
    design_repositories_synced_count = IntegerField(null=True)
    geo_node = ForeignKeyField(column_name='geo_node_id', field='id', model=GeoNodes, unique=True)
    job_artifacts_count = IntegerField(null=True)
    job_artifacts_failed_count = IntegerField(null=True)
    job_artifacts_synced_count = IntegerField(null=True)
    job_artifacts_synced_missing_on_primary_count = IntegerField(null=True)
    last_event_date = DateTimeField(null=True)
    last_event_id = IntegerField(null=True)
    last_successful_status_check_at = DateTimeField(null=True)
    lfs_objects_count = IntegerField(null=True)
    lfs_objects_failed_count = IntegerField(null=True)
    lfs_objects_synced_count = IntegerField(null=True)
    lfs_objects_synced_missing_on_primary_count = IntegerField(null=True)
    projects_count = IntegerField(null=True)
    replication_slots_count = IntegerField(null=True)
    replication_slots_max_retained_wal_bytes = BigIntegerField(null=True)
    replication_slots_used_count = IntegerField(null=True)
    repositories_checksum_failed_count = IntegerField(null=True)
    repositories_checksum_mismatch_count = IntegerField(null=True)
    repositories_checksummed_count = IntegerField(null=True)
    repositories_failed_count = IntegerField(null=True)
    repositories_retrying_verification_count = IntegerField(null=True)
    repositories_synced_count = IntegerField(null=True)
    repositories_verification_failed_count = IntegerField(null=True)
    repositories_verified_count = IntegerField(null=True)
    revision = CharField(null=True)
    status = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    status_message = CharField(null=True)
    storage_configuration_digest = BlobField(null=True)
    updated_at = DateTimeField()
    version = CharField(null=True)
    wikis_checksum_failed_count = IntegerField(null=True)
    wikis_checksum_mismatch_count = IntegerField(null=True)
    wikis_checksummed_count = IntegerField(null=True)
    wikis_failed_count = IntegerField(null=True)
    wikis_retrying_verification_count = IntegerField(null=True)
    wikis_synced_count = IntegerField(null=True)
    wikis_verification_failed_count = IntegerField(null=True)
    wikis_verified_count = IntegerField(null=True)

    class Meta:
        table_name = 'geo_node_statuses'

class GitlabSubscriptionHistories(BaseModel):
    auto_renew = BooleanField(null=True)
    change_type = SmallIntegerField(null=True)
    created_at = DateTimeField(null=True)
    end_date = DateField(null=True)
    gitlab_subscription_created_at = DateTimeField(null=True)
    gitlab_subscription_id = BigIntegerField(index=True)
    gitlab_subscription_updated_at = DateTimeField(null=True)
    hosted_plan_id = IntegerField(null=True)
    id = BigAutoField()
    max_seats_used = IntegerField(null=True)
    namespace_id = IntegerField(null=True)
    seats = IntegerField(null=True)
    start_date = DateField(null=True)
    trial = BooleanField(null=True)
    trial_ends_on = DateField(null=True)
    trial_starts_on = DateField(null=True)

    class Meta:
        table_name = 'gitlab_subscription_histories'

class Plans(BaseModel):
    created_at = DateTimeField()
    name = CharField(null=True, unique=True)
    title = CharField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'plans'

class GitlabSubscriptions(BaseModel):
    auto_renew = BooleanField(null=True)
    created_at = DateTimeField()
    end_date = DateField(null=True)
    hosted_plan = ForeignKeyField(column_name='hosted_plan_id', field='id', model=Plans, null=True)
    id = BigAutoField()
    max_seats_used = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, null=True, unique=True)
    seats = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    seats_in_use = IntegerField(constraints=[SQL("DEFAULT 0")])
    seats_owed = IntegerField(constraints=[SQL("DEFAULT 0")])
    start_date = DateField(null=True)
    trial = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    trial_ends_on = DateField(null=True)
    trial_starts_on = DateField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'gitlab_subscriptions'
        indexes = (
            (('end_date', 'namespace'), False),
        )

class GpgKeys(BaseModel):
    created_at = DateTimeField()
    fingerprint = BlobField(null=True, unique=True)
    key = TextField(null=True)
    primary_keyid = BlobField(null=True, unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'gpg_keys'

class GpgKeySubkeys(BaseModel):
    fingerprint = BlobField(null=True, unique=True)
    gpg_key = ForeignKeyField(column_name='gpg_key_id', field='id', model=GpgKeys)
    keyid = BlobField(null=True, unique=True)

    class Meta:
        table_name = 'gpg_key_subkeys'

class GpgSignatures(BaseModel):
    commit_sha = BlobField(null=True, unique=True)
    created_at = DateTimeField()
    gpg_key = ForeignKeyField(column_name='gpg_key_id', field='id', model=GpgKeys, null=True)
    gpg_key_primary_keyid = BlobField(index=True, null=True)
    gpg_key_subkey = ForeignKeyField(column_name='gpg_key_subkey_id', field='id', model=GpgKeySubkeys, null=True)
    gpg_key_user_email = TextField(null=True)
    gpg_key_user_name = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()
    verification_status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'gpg_signatures'

class GrafanaIntegrations(BaseModel):
    created_at = DateTimeField()
    enabled = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    encrypted_token = CharField()
    encrypted_token_iv = CharField()
    grafana_url = CharField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'grafana_integrations'

class GroupCustomAttributes(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    key = CharField()
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        table_name = 'group_custom_attributes'
        indexes = (
            (('group', 'key'), True),
            (('key', 'value'), False),
        )

class GroupDeletionSchedules(BaseModel):
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, primary_key=True)
    marked_for_deletion_on = DateField(index=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'group_deletion_schedules'

class GroupDeployKeys(BaseModel):
    created_at = DateTimeField()
    expires_at = DateTimeField(null=True)
    fingerprint = TextField(unique=True)
    fingerprint_sha256 = BlobField(index=True, null=True)
    id = BigAutoField()
    key = TextField()
    last_used_at = DateTimeField(null=True)
    title = TextField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'group_deploy_keys'

class GroupDeployKeysGroups(BaseModel):
    can_push = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    group_deploy_key = ForeignKeyField(column_name='group_deploy_key_id', field='id', model=GroupDeployKeys)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'group_deploy_keys_groups'
        indexes = (
            (('group', 'group_deploy_key'), True),
        )

class GroupDeployTokens(BaseModel):
    created_at = DateTimeField()
    deploy_token = ForeignKeyField(column_name='deploy_token_id', field='id', model=DeployTokens)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'group_deploy_tokens'
        indexes = (
            (('group', 'deploy_token'), True),
        )

class GroupGroupLinks(BaseModel):
    created_at = DateTimeField()
    expires_at = DateField(null=True)
    group_access = SmallIntegerField(constraints=[SQL("DEFAULT 30")])
    id = BigAutoField()
    shared_group = ForeignKeyField(column_name='shared_group_id', field='id', model=Namespaces)
    shared_with_group = ForeignKeyField(backref='namespaces_shared_with_group_set', column_name='shared_with_group_id', field='id', model=Namespaces)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'group_group_links'
        indexes = (
            (('shared_group', 'shared_with_group'), True),
        )

class GroupImportStates(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, primary_key=True)
    jid = TextField(null=True)
    last_error = TextField(null=True)
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'group_import_states'

class GroupWikiRepositories(BaseModel):
    disk_path = TextField(unique=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, primary_key=True)
    shard = ForeignKeyField(column_name='shard_id', field='id', model=Shards)

    class Meta:
        table_name = 'group_wiki_repositories'

class HistoricalData(BaseModel):
    active_user_count = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    date = DateField(null=True)
    recorded_at = DateTimeField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'historical_data'

class SamlProviders(BaseModel):
    certificate_fingerprint = CharField()
    default_membership_role = SmallIntegerField(constraints=[SQL("DEFAULT 10")])
    enabled = BooleanField()
    enforced_group_managed_accounts = BooleanField(constraints=[SQL("DEFAULT false")])
    enforced_sso = BooleanField(constraints=[SQL("DEFAULT false")])
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    prohibited_outer_forks = BooleanField(constraints=[SQL("DEFAULT true")])
    sso_url = CharField()

    class Meta:
        table_name = 'saml_providers'

class Identities(BaseModel):
    created_at = DateTimeField(null=True)
    extern_uid = CharField(null=True)
    provider = CharField(null=True)
    saml_provider = ForeignKeyField(column_name='saml_provider_id', field='id', model=SamlProviders, null=True)
    secondary_extern_uid = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(index=True, null=True)

    class Meta:
        table_name = 'identities'
        indexes = (
            (('provider'), False),
        )

class ImportExportUploads(BaseModel):
    export_file = TextField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True, unique=True)
    import_file = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField(index=True)

    class Meta:
        table_name = 'import_export_uploads'

class ImportFailures(BaseModel):
    correlation_id_value = CharField(index=True, null=True)
    created_at = DateTimeField()
    exception_class = CharField(null=True)
    exception_message = CharField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    id = BigAutoField()
    project_id = BigIntegerField(index=True, null=True)
    relation_index = IntegerField(null=True)
    relation_key = CharField(null=True)
    retry_count = IntegerField(null=True)
    source = CharField(null=True)

    class Meta:
        table_name = 'import_failures'
        indexes = (
            (('project_id', 'correlation_id_value'), False),
        )

class IndexStatuses(BaseModel):
    created_at = DateTimeField()
    indexed_at = DateTimeField(null=True)
    last_commit = CharField(null=True)
    last_wiki_commit = BlobField(null=True)
    note = TextField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    updated_at = DateTimeField()
    wiki_indexed_at = DateTimeField(null=True)

    class Meta:
        table_name = 'index_statuses'

class Insights(BaseModel):
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'insights'

class InternalIds(BaseModel):
    id = BigAutoField()
    last_value = IntegerField()
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    usage = IntegerField()

    class Meta:
        table_name = 'internal_ids'
        indexes = (
            (('usage', 'namespace'), True),
            (('usage', 'project'), True),
        )

class IpRestrictions(BaseModel):
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    range = CharField()

    class Meta:
        table_name = 'ip_restrictions'

class IssuableSeverities(BaseModel):
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)
    severity = SmallIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'issuable_severities'

class IssuableSlas(BaseModel):
    due_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)

    class Meta:
        table_name = 'issuable_slas'

class IssueAssignees(BaseModel):
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'issue_assignees'
        indexes = (
            (('issue', 'user'), True),
        )
        primary_key = CompositeKey('issue', 'user')

class IssueEmailParticipants(BaseModel):
    created_at = DateTimeField()
    email = TextField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issue_email_participants'
        indexes = (
            (('issue', 'email'), True),
        )

class IssueLinks(BaseModel):
    created_at = DateTimeField(null=True)
    link_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    source = ForeignKeyField(column_name='source_id', field='id', model=Issues)
    target = ForeignKeyField(backref='issues_target_set', column_name='target_id', field='id', model=Issues)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'issue_links'
        indexes = (
            (('source', 'target'), True),
        )

class IssueMetrics(BaseModel):
    created_at = DateTimeField()
    first_added_to_board_at = DateTimeField(null=True)
    first_associated_with_milestone_at = DateTimeField(null=True)
    first_mentioned_in_commit_at = DateTimeField(null=True)
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issue_metrics'
        indexes = (
            (('issue', 'first_mentioned_in_commit_at', 'first_associated_with_milestone_at', 'first_added_to_board_at'), False),
        )

class IssueTrackerData(BaseModel):
    created_at = DateTimeField()
    encrypted_issues_url = CharField(null=True)
    encrypted_issues_url_iv = CharField(null=True)
    encrypted_new_issue_url = CharField(null=True)
    encrypted_new_issue_url_iv = CharField(null=True)
    encrypted_project_url = CharField(null=True)
    encrypted_project_url_iv = CharField(null=True)
    id = BigAutoField()
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issue_tracker_data'

class IssueUserMentions(BaseModel):
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)

    class Meta:
        table_name = 'issue_user_mentions'
        indexes = (
            (('issue', 'note'), True),
        )

class PrometheusAlertEvents(BaseModel):
    ended_at = DateTimeField(null=True)
    id = BigAutoField()
    payload_key = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    prometheus_alert = ForeignKeyField(column_name='prometheus_alert_id', field='id', model=PrometheusAlerts)
    started_at = DateTimeField()
    status = SmallIntegerField(null=True)

    class Meta:
        table_name = 'prometheus_alert_events'
        indexes = (
            (('project', 'status'), False),
            (('prometheus_alert', 'payload_key'), True),
        )

class IssuesPrometheusAlertEvents(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    prometheus_alert_event = ForeignKeyField(column_name='prometheus_alert_event_id', field='id', model=PrometheusAlertEvents)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issues_prometheus_alert_events'
        indexes = (
            (('issue', 'prometheus_alert_event'), True),
        )
        primary_key = CompositeKey('issue', 'prometheus_alert_event')

class SelfManagedPrometheusAlertEvents(BaseModel):
    ended_at = DateTimeField(null=True)
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments, null=True)
    id = BigAutoField()
    payload_key = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    query_expression = CharField(null=True)
    started_at = DateTimeField()
    status = SmallIntegerField()
    title = CharField()

    class Meta:
        table_name = 'self_managed_prometheus_alert_events'
        indexes = (
            (('project', 'payload_key'), True),
        )

class IssuesSelfManagedPrometheusAlertEvents(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    self_managed_prometheus_alert_event = ForeignKeyField(column_name='self_managed_prometheus_alert_event_id', field='id', model=SelfManagedPrometheusAlertEvents)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'issues_self_managed_prometheus_alert_events'
        indexes = (
            (('issue', 'self_managed_prometheus_alert_event'), True),
        )
        primary_key = CompositeKey('issue', 'self_managed_prometheus_alert_event')

class JiraConnectInstallations(BaseModel):
    base_url = CharField(null=True)
    client_key = CharField(null=True, unique=True)
    encrypted_shared_secret = CharField(null=True)
    encrypted_shared_secret_iv = CharField(null=True)
    id = BigAutoField()

    class Meta:
        table_name = 'jira_connect_installations'

class JiraConnectSubscriptions(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    jira_connect_installation = ForeignKeyField(column_name='jira_connect_installation_id', field='id', model=JiraConnectInstallations)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'jira_connect_subscriptions'
        indexes = (
            (('jira_connect_installation', 'namespace'), True),
        )

class JiraImports(BaseModel):
    created_at = DateTimeField()
    error_message = TextField(null=True)
    failed_to_import_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    finished_at = DateTimeField(null=True)
    id = BigAutoField()
    imported_issues_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    jid = CharField(null=True)
    jira_project_key = CharField()
    jira_project_name = CharField()
    jira_project_xid = BigIntegerField()
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    scheduled_at = DateTimeField(null=True)
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    total_issue_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'jira_imports'
        indexes = (
            (('project', 'jira_project_key'), False),
        )

class JiraTrackerData(BaseModel):
    created_at = DateTimeField()
    deployment_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    encrypted_api_url = CharField(null=True)
    encrypted_api_url_iv = CharField(null=True)
    encrypted_password = CharField(null=True)
    encrypted_password_iv = CharField(null=True)
    encrypted_url = CharField(null=True)
    encrypted_url_iv = CharField(null=True)
    encrypted_username = CharField(null=True)
    encrypted_username_iv = CharField(null=True)
    id = BigAutoField()
    issues_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    jira_issue_transition_id = CharField(null=True)
    project_key = TextField(null=True)
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    updated_at = DateTimeField()
    vulnerabilities_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    vulnerabilities_issuetype = TextField(null=True)

    class Meta:
        table_name = 'jira_tracker_data'

class Keys(BaseModel):
    created_at = DateTimeField(null=True)
    expires_at = DateTimeField(null=True)
    fingerprint = CharField(null=True, unique=True)
    fingerprint_sha256 = BlobField(index=True, null=True)
    key = TextField(null=True)
    last_used_at = DateTimeField(index=True, null=True)
    public = BooleanField(constraints=[SQL("DEFAULT false")])
    title = CharField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(index=True, null=True)

    class Meta:
        table_name = 'keys'
        indexes = (
            (('id', 'type'), True),
        )

class LabelLinks(BaseModel):
    created_at = DateTimeField(null=True)
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels, null=True)
    target_id = IntegerField(null=True)
    target_type = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'label_links'
        indexes = (
            (('label', 'target_type'), False),
            (('target_id', 'label', 'target_type'), False),
            (('target_id', 'target_type'), False),
        )

class LabelPriorities(BaseModel):
    created_at = DateTimeField()
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels)
    priority = IntegerField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'label_priorities'
        indexes = (
            (('project', 'label'), True),
        )

class LdapGroupLinks(BaseModel):
    cn = CharField(null=True)
    created_at = DateTimeField(null=True)
    filter = CharField(null=True)
    group_access = IntegerField()
    group_id = IntegerField()
    provider = CharField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'ldap_group_links'

class LfsFileLocks(BaseModel):
    created_at = DateTimeField()
    path = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'lfs_file_locks'
        indexes = (
            (('project', 'path'), True),
        )

class LfsObjects(BaseModel):
    created_at = DateTimeField(null=True)
    file = CharField(null=True)
    file_store = IntegerField(constraints=[SQL("DEFAULT 1")], index=True, null=True)
    oid = CharField(unique=True)
    size = BigIntegerField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'lfs_objects'

class LfsObjectsProjects(BaseModel):
    created_at = DateTimeField(null=True)
    lfs_object_id = IntegerField(index=True)
    project_id = IntegerField()
    repository_type = SmallIntegerField(null=True)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'lfs_objects_projects'
        indexes = (
            (('project_id', 'lfs_object_id'), False),
        )

class Licenses(BaseModel):
    created_at = DateTimeField(null=True)
    data = TextField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'licenses'

class Lists(BaseModel):
    board = ForeignKeyField(column_name='board_id', field='id', model=Boards)
    created_at = DateTimeField()
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels, null=True)
    limit_metric = CharField(null=True)
    list_type = IntegerField(constraints=[SQL("DEFAULT 1")], index=True)
    max_issue_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    max_issue_weight = IntegerField(constraints=[SQL("DEFAULT 0")])
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones, null=True)
    position = IntegerField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'lists'
        indexes = (
            (('board', 'label'), True),
        )

class ListUserPreferences(BaseModel):
    collapsed = BooleanField(null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    list = ForeignKeyField(column_name='list_id', field='id', model=Lists)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'list_user_preferences'
        indexes = (
            (('user', 'list'), True),
        )

class Members(BaseModel):
    access_level = IntegerField(index=True)
    created_at = DateTimeField(index=True, null=True)
    created_by_id = IntegerField(null=True)
    expires_at = DateField(index=True, null=True)
    invite_accepted_at = DateTimeField(null=True)
    invite_email = CharField(index=True, null=True)
    invite_token = CharField(null=True, unique=True)
    ldap = BooleanField(constraints=[SQL("DEFAULT false")])
    notification_level = IntegerField()
    override = BooleanField(constraints=[SQL("DEFAULT false")])
    requested_at = DateTimeField(index=True, null=True)
    source_id = IntegerField()
    source_type = CharField()
    type = CharField(null=True)
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'members'
        indexes = (
            (('source_id', 'source_type'), False),
            (('source_id', 'source_type'), False),
            (('user', 'created_at'), False),
        )

class MergeRequestAssignees(BaseModel):
    created_at = DateTimeField(null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'merge_request_assignees'
        indexes = (
            (('merge_request', 'user'), True),
        )

class MergeRequestBlocks(BaseModel):
    blocked_merge_request = ForeignKeyField(column_name='blocked_merge_request_id', field='id', model=MergeRequests)
    blocking_merge_request = ForeignKeyField(backref='merge_requests_blocking_merge_request_set', column_name='blocking_merge_request_id', field='id', model=MergeRequests)
    created_at = DateTimeField()
    id = BigAutoField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'merge_request_blocks'
        indexes = (
            (('blocking_merge_request', 'blocked_merge_request'), True),
        )

class MergeRequestCleanupSchedules(BaseModel):
    completed_at = DateTimeField(null=True)
    created_at = DateTimeField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, primary_key=True)
    scheduled_at = DateTimeField(index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'merge_request_cleanup_schedules'

class MergeRequestContextCommits(BaseModel):
    author_email = TextField(null=True)
    author_name = TextField(null=True)
    authored_date = DateTimeField(null=True)
    committed_date = DateTimeField(null=True)
    committer_email = TextField(null=True)
    committer_name = TextField(null=True)
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    message = TextField(null=True)
    relative_order = IntegerField()
    sha = BlobField()

    class Meta:
        table_name = 'merge_request_context_commits'
        indexes = (
            (('merge_request', 'sha'), True),
        )

class MergeRequestContextCommitDiffFiles(BaseModel):
    a_mode = CharField()
    b_mode = CharField()
    binary = BooleanField(null=True)
    deleted_file = BooleanField()
    diff = TextField(null=True)
    merge_request_context_commit = ForeignKeyField(column_name='merge_request_context_commit_id', field='id', model=MergeRequestContextCommits, null=True)
    new_file = BooleanField()
    new_path = TextField()
    old_path = TextField()
    relative_order = IntegerField()
    renamed_file = BooleanField()
    sha = BlobField()
    too_large = BooleanField()

    class Meta:
        table_name = 'merge_request_context_commit_diff_files'
        indexes = (
            (('merge_request_context_commit', 'sha'), False),
        )
        primary_key = False

class MergeRequestDiffCommits(BaseModel):
    author_email = TextField(null=True)
    author_name = TextField(null=True)
    authored_date = DateTimeField(null=True)
    committed_date = DateTimeField(null=True)
    committer_email = TextField(null=True)
    committer_name = TextField(null=True)
    merge_request_diff = ForeignKeyField(column_name='merge_request_diff_id', field='id', model=MergeRequestDiffs)
    message = TextField(null=True)
    relative_order = IntegerField()
    sha = BlobField(index=True)

    class Meta:
        table_name = 'merge_request_diff_commits'
        indexes = (
            (('merge_request_diff', 'relative_order'), True),
        )
        primary_key = CompositeKey('merge_request_diff', 'relative_order')

class MergeRequestDiffDetails(BaseModel):
    merge_request_diff = ForeignKeyField(column_name='merge_request_diff_id', field='id', model=MergeRequestDiffs, primary_key=True)
    verification_checksum = BlobField(null=True)
    verification_failure = TextField(null=True)
    verification_retry_at = DateTimeField(null=True)
    verification_retry_count = SmallIntegerField(null=True)
    verified_at = DateTimeField(null=True)

    class Meta:
        table_name = 'merge_request_diff_details'

class MergeRequestDiffFiles(BaseModel):
    a_mode = CharField()
    b_mode = CharField()
    binary = BooleanField(null=True)
    deleted_file = BooleanField()
    diff = TextField(null=True)
    external_diff_offset = IntegerField(null=True)
    external_diff_size = IntegerField(null=True)
    merge_request_diff = ForeignKeyField(column_name='merge_request_diff_id', field='id', model=MergeRequestDiffs)
    new_file = BooleanField()
    new_path = TextField()
    old_path = TextField()
    relative_order = IntegerField()
    renamed_file = BooleanField()
    too_large = BooleanField()

    class Meta:
        table_name = 'merge_request_diff_files'
        indexes = (
            (('merge_request_diff', 'relative_order'), True),
        )
        primary_key = CompositeKey('merge_request_diff', 'relative_order')

class MergeRequestMetrics(BaseModel):
    added_lines = IntegerField(null=True)
    commits_count = IntegerField(null=True)
    created_at = DateTimeField()
    diff_size = IntegerField(null=True)
    first_approved_at = DateTimeField(null=True)
    first_comment_at = DateTimeField(null=True)
    first_commit_at = DateTimeField(null=True)
    first_deployed_to_production_at = DateTimeField(index=True, null=True)
    first_reassigned_at = DateTimeField(null=True)
    last_commit_at = DateTimeField(null=True)
    latest_build_finished_at = DateTimeField(null=True)
    latest_build_started_at = DateTimeField(null=True)
    latest_closed_at = DateTimeField(index=True, null=True)
    latest_closed_by = ForeignKeyField(column_name='latest_closed_by_id', field='id', model=Users, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, unique=True)
    merged_at = DateTimeField(index=True, null=True)
    merged_by = ForeignKeyField(backref='users_merged_by_set', column_name='merged_by_id', field='id', model=Users, null=True)
    modified_paths_size = IntegerField(null=True)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    removed_lines = IntegerField(null=True)
    target_project = ForeignKeyField(column_name='target_project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'merge_request_metrics'
        indexes = (
            (('merge_request', 'merged_at'), False),
            (('target_project', 'merged_at', 'id'), False),
        )

class MergeRequestReviewers(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'merge_request_reviewers'
        indexes = (
            (('merge_request', 'user'), True),
        )

class MergeRequestUserMentions(BaseModel):
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, unique=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)

    class Meta:
        table_name = 'merge_request_user_mentions'
        indexes = (
            (('merge_request', 'note'), True),
        )

class MergeRequestsClosingIssues(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'merge_requests_closing_issues'

class MergeTrains(BaseModel):
    created_at = DateTimeField()
    duration = IntegerField(null=True)
    id = BigAutoField()
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, unique=True)
    merged_at = DateTimeField(null=True)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    target_branch = TextField()
    target_project = ForeignKeyField(column_name='target_project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'merge_trains'
        indexes = (
            (('target_project', 'target_branch', 'status'), False),
        )

class MetricsDashboardAnnotations(BaseModel):
    cluster = ForeignKeyField(column_name='cluster_id', field='id', model=Clusters, null=True)
    dashboard_path = CharField()
    description = TextField()
    ending_at = DateTimeField(null=True)
    environment = ForeignKeyField(column_name='environment_id', field='id', model=Environments, null=True)
    id = BigAutoField()
    panel_xid = CharField(null=True)
    starting_at = DateTimeField()

    class Meta:
        table_name = 'metrics_dashboard_annotations'
        indexes = (
            ((), False),
            (('cluster', 'dashboard_path', 'starting_at', 'ending_at'), False),
            (('environment', 'dashboard_path', 'starting_at', 'ending_at'), False),
        )

class MetricsUsersStarredDashboards(BaseModel):
    created_at = DateTimeField()
    dashboard_path = TextField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'metrics_users_starred_dashboards'
        indexes = (
            (('user', 'project', 'dashboard_path'), True),
        )

class MilestoneReleases(BaseModel):
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones)
    release = ForeignKeyField(column_name='release_id', field='id', model=Releases)

    class Meta:
        table_name = 'milestone_releases'
        indexes = (
            (('milestone', 'release'), True),
        )
        primary_key = CompositeKey('milestone', 'release')

class NamespaceAggregationSchedules(BaseModel):
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, primary_key=True)

    class Meta:
        table_name = 'namespace_aggregation_schedules'

class NamespaceLimits(BaseModel):
    additional_purchased_storage_ends_on = DateField(null=True)
    additional_purchased_storage_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, primary_key=True)
    temporary_storage_increase_ends_on = DateField(null=True)

    class Meta:
        table_name = 'namespace_limits'

class NamespaceRootStorageStatistics(BaseModel):
    build_artifacts_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    lfs_objects_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, primary_key=True)
    packages_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    pipeline_artifacts_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    repository_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    snippets_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    storage_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()
    uploads_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    wiki_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'namespace_root_storage_statistics'

class NamespaceSettings(BaseModel):
    allow_mfa_for_subgroups = BooleanField(constraints=[SQL("DEFAULT true")])
    created_at = DateTimeField()
    default_branch_name = TextField(null=True)
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, primary_key=True)
    prevent_forking_outside_group = BooleanField(constraints=[SQL("DEFAULT false")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'namespace_settings'

class NamespaceStatistics(BaseModel):
    namespace = ForeignKeyField(column_name='namespace_id', field='id', model=Namespaces, unique=True)
    shared_runners_seconds = IntegerField(constraints=[SQL("DEFAULT 0")])
    shared_runners_seconds_last_reset = DateTimeField(null=True)

    class Meta:
        table_name = 'namespace_statistics'

class NoteDiffFiles(BaseModel):
    a_mode = CharField()
    b_mode = CharField()
    deleted_file = BooleanField()
    diff = TextField()
    diff_note = ForeignKeyField(column_name='diff_note_id', field='id', model=Notes, unique=True)
    new_file = BooleanField()
    new_path = TextField()
    old_path = TextField()
    renamed_file = BooleanField()

    class Meta:
        table_name = 'note_diff_files'

class NotificationSettings(BaseModel):
    change_reviewer_merge_request = BooleanField(null=True)
    close_issue = BooleanField(null=True)
    close_merge_request = BooleanField(null=True)
    created_at = DateTimeField()
    failed_pipeline = BooleanField(null=True)
    fixed_pipeline = BooleanField(null=True)
    issue_due = BooleanField(null=True)
    level = IntegerField(constraints=[SQL("DEFAULT 0")])
    merge_merge_request = BooleanField(null=True)
    moved_project = BooleanField(constraints=[SQL("DEFAULT true")])
    new_epic = BooleanField(null=True)
    new_issue = BooleanField(null=True)
    new_merge_request = BooleanField(null=True)
    new_note = BooleanField(null=True)
    new_release = BooleanField(null=True)
    notification_email = CharField(null=True)
    push_to_merge_request = BooleanField(null=True)
    reassign_issue = BooleanField(null=True)
    reassign_merge_request = BooleanField(null=True)
    reopen_issue = BooleanField(null=True)
    reopen_merge_request = BooleanField(null=True)
    source_id = IntegerField(null=True)
    source_type = CharField(null=True)
    success_pipeline = BooleanField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'notification_settings'
        indexes = (
            (('source_id', 'source_type'), False),
            (('user', 'source_id', 'source_type'), True),
        )

class OauthAccessGrants(BaseModel):
    application_id = IntegerField()
    created_at = DateTimeField()
    expires_in = IntegerField()
    redirect_uri = TextField()
    resource_owner_id = IntegerField()
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        table_name = 'oauth_access_grants'
        indexes = (
            (('resource_owner_id', 'application_id', 'created_at'), False),
        )

class OauthAccessTokens(BaseModel):
    application_id = IntegerField(index=True, null=True)
    created_at = DateTimeField()
    expires_in = IntegerField(null=True)
    refresh_token = CharField(null=True, unique=True)
    resource_owner_id = IntegerField(index=True, null=True)
    revoked_at = DateTimeField(null=True)
    scopes = CharField(null=True)
    token = CharField(unique=True)

    class Meta:
        table_name = 'oauth_access_tokens'

class OauthOpenidRequests(BaseModel):
    access_grant = ForeignKeyField(column_name='access_grant_id', field='id', model=OauthAccessGrants)
    nonce = CharField()

    class Meta:
        table_name = 'oauth_openid_requests'

class OpenProjectTrackerData(BaseModel):
    closed_status_id = CharField(null=True)
    created_at = DateTimeField()
    encrypted_api_url = CharField(null=True)
    encrypted_api_url_iv = CharField(null=True)
    encrypted_token = CharField(null=True)
    encrypted_token_iv = CharField(null=True)
    encrypted_url = CharField(null=True)
    encrypted_url_iv = CharField(null=True)
    id = BigAutoField()
    project_identifier_code = CharField(null=True)
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'open_project_tracker_data'

class OperationsFeatureFlags(BaseModel):
    active = BooleanField()
    created_at = DateTimeField()
    description = TextField(null=True)
    id = BigAutoField()
    iid = IntegerField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    version = SmallIntegerField(constraints=[SQL("DEFAULT 1")])

    class Meta:
        table_name = 'operations_feature_flags'
        indexes = (
            (('project', 'iid'), True),
            (('project', 'name'), True),
        )

class OperationsFeatureFlagScopes(BaseModel):
    active = BooleanField()
    created_at = DateTimeField()
    environment_scope = CharField(constraints=[SQL("DEFAULT '*'::character varying")])
    feature_flag = ForeignKeyField(column_name='feature_flag_id', field='id', model=OperationsFeatureFlags)
    id = BigAutoField()
    strategies = BinaryJSONField(constraints=[SQL("DEFAULT '[{\"name\": \"default\", \"parameters\": {}}]'::jsonb")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'operations_feature_flag_scopes'
        indexes = (
            (('feature_flag', 'environment_scope'), True),
        )

class OperationsFeatureFlagsClients(BaseModel):
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    token_encrypted = CharField(null=True)

    class Meta:
        table_name = 'operations_feature_flags_clients'
        indexes = (
            (('project', 'token_encrypted'), True),
        )

class OperationsFeatureFlagsIssues(BaseModel):
    feature_flag = ForeignKeyField(column_name='feature_flag_id', field='id', model=OperationsFeatureFlags)
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)

    class Meta:
        table_name = 'operations_feature_flags_issues'
        indexes = (
            (('feature_flag', 'issue'), True),
        )

class OperationsStrategies(BaseModel):
    feature_flag = ForeignKeyField(column_name='feature_flag_id', field='id', model=OperationsFeatureFlags)
    id = BigAutoField()
    name = CharField()
    parameters = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])

    class Meta:
        table_name = 'operations_strategies'

class OperationsScopes(BaseModel):
    environment_scope = CharField()
    id = BigAutoField()
    strategy = ForeignKeyField(column_name='strategy_id', field='id', model=OperationsStrategies)

    class Meta:
        table_name = 'operations_scopes'
        indexes = (
            (('strategy', 'environment_scope'), True),
        )

class OperationsUserLists(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    iid = IntegerField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    user_xids = TextField(constraints=[SQL("DEFAULT ''::text")])

    class Meta:
        table_name = 'operations_user_lists'
        indexes = (
            (('project', 'iid'), True),
            (('project', 'name'), True),
        )

class OperationsStrategiesUserLists(BaseModel):
    id = BigAutoField()
    strategy = ForeignKeyField(column_name='strategy_id', field='id', model=OperationsStrategies)
    user_list = ForeignKeyField(column_name='user_list_id', field='id', model=OperationsUserLists)

    class Meta:
        table_name = 'operations_strategies_user_lists'
        indexes = (
            (('strategy', 'user_list'), True),
        )

class PackagesPackages(BaseModel):
    created_at = DateTimeField()
    creator = ForeignKeyField(column_name='creator_id', field='id', model=Users, null=True)
    id = BigAutoField()
    name = CharField(index=True)
    package_type = SmallIntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    version = CharField(null=True)

    class Meta:
        table_name = 'packages_packages'
        indexes = (
            (('id', 'created_at'), False),
            (('project', 'created_at'), False),
            (('project', 'name'), False),
            (('project', 'name', 'version'), True),
            (('project', 'name', 'version', 'package_type'), False),
            (('project', 'package_type'), False),
            (('project', 'version'), False),
        )

class PackagesBuildInfos(BaseModel):
    id = BigAutoField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)

    class Meta:
        table_name = 'packages_build_infos'

class PackagesComposerMetadata(BaseModel):
    composer_json = BinaryJSONField(constraints=[SQL("DEFAULT '{}'::jsonb")])
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages, primary_key=True)
    target_sha = BlobField()

    class Meta:
        table_name = 'packages_composer_metadata'
        indexes = (
            (('package', 'target_sha'), True),
        )

class PackagesPackageFiles(BaseModel):
    created_at = DateTimeField()
    file = TextField()
    file_md5 = BlobField(null=True)
    file_name = CharField()
    file_sha1 = BlobField(null=True)
    file_sha256 = BlobField(null=True)
    file_store = IntegerField(constraints=[SQL("DEFAULT 1")], index=True, null=True)
    id = BigAutoField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)
    size = BigIntegerField(null=True)
    updated_at = DateTimeField()
    verification_checksum = BlobField(index=True, null=True)
    verification_failure = CharField(index=True, null=True)
    verification_retry_at = DateTimeField(null=True)
    verification_retry_count = IntegerField(null=True)
    verified_at = DateTimeField(null=True)

    class Meta:
        table_name = 'packages_package_files'
        indexes = (
            (('package', 'file_name'), False),
        )

class PackagesConanFileMetadata(BaseModel):
    conan_file_type = SmallIntegerField()
    conan_package_reference = CharField(null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    package_file = ForeignKeyField(column_name='package_file_id', field='id', model=PackagesPackageFiles, unique=True)
    package_revision = CharField(null=True)
    recipe_revision = CharField(constraints=[SQL("DEFAULT '0'::character varying")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'packages_conan_file_metadata'

class PackagesConanMetadata(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    package_channel = CharField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)
    package_username = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'packages_conan_metadata'
        indexes = (
            (('package', 'package_username', 'package_channel'), True),
        )

class PackagesDependencies(BaseModel):
    id = BigAutoField()
    name = CharField()
    version_pattern = CharField()

    class Meta:
        table_name = 'packages_dependencies'
        indexes = (
            (('name', 'version_pattern'), True),
        )

class PackagesDependencyLinks(BaseModel):
    dependency = ForeignKeyField(column_name='dependency_id', field='id', model=PackagesDependencies)
    dependency_type = SmallIntegerField()
    id = BigAutoField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)

    class Meta:
        table_name = 'packages_dependency_links'
        indexes = (
            (('package', 'dependency', 'dependency_type'), True),
        )

class PackagesEvents(BaseModel):
    created_at = DateTimeField()
    event_scope = SmallIntegerField()
    event_type = SmallIntegerField()
    id = BigAutoField()
    originator = BigIntegerField(null=True)
    originator_type = SmallIntegerField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages, null=True)

    class Meta:
        table_name = 'packages_events'

class PackagesMavenMetadata(BaseModel):
    app_group = CharField()
    app_name = CharField()
    app_version = CharField(null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)
    path = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'packages_maven_metadata'
        indexes = (
            (('package', 'path'), False),
        )

class PackagesNugetDependencyLinkMetadata(BaseModel):
    dependency_link = ForeignKeyField(column_name='dependency_link_id', field='id', model=PackagesDependencyLinks, primary_key=True)
    target_framework = TextField()

    class Meta:
        table_name = 'packages_nuget_dependency_link_metadata'

class PackagesNugetMetadata(BaseModel):
    icon_url = TextField(null=True)
    license_url = TextField(null=True)
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages, primary_key=True)
    project_url = TextField(null=True)

    class Meta:
        table_name = 'packages_nuget_metadata'

class PackagesPackageFileBuildInfos(BaseModel):
    id = BigAutoField()
    package_file = ForeignKeyField(column_name='package_file_id', field='id', model=PackagesPackageFiles)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)

    class Meta:
        table_name = 'packages_package_file_build_infos'

class PackagesPypiMetadata(BaseModel):
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages, primary_key=True)
    required_python = TextField(null=True)

    class Meta:
        table_name = 'packages_pypi_metadata'

class PackagesTags(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    name = CharField()
    package = ForeignKeyField(column_name='package_id', field='id', model=PackagesPackages)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'packages_tags'
        indexes = (
            (('package', 'updated_at'), False),
        )

class PagesDeployments(BaseModel):
    ci_build = ForeignKeyField(column_name='ci_build_id', field='id', model=CiBuilds, null=True)
    created_at = DateTimeField()
    file = TextField()
    file_count = IntegerField()
    file_sha256 = BlobField()
    file_store = SmallIntegerField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    size = IntegerField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'pages_deployments'

class PagesDomains(BaseModel):
    auto_ssl_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    auto_ssl_failed = BooleanField(constraints=[SQL("DEFAULT false")])
    certificate = TextField(null=True)
    certificate_source = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    certificate_valid_not_after = DateTimeField(index=True, null=True)
    certificate_valid_not_before = DateTimeField(null=True)
    domain = CharField(null=True)
    enabled_until = DateTimeField(null=True)
    encrypted_key = TextField(null=True)
    encrypted_key_iv = CharField(null=True)
    encrypted_key_salt = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    remove_at = DateTimeField(index=True, null=True)
    scope = SmallIntegerField(constraints=[SQL("DEFAULT 2")], index=True)
    usage = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    verification_code = CharField()
    verified_at = DateTimeField(index=True, null=True)
    wildcard = BooleanField(constraints=[SQL("DEFAULT false")], index=True)

    class Meta:
        table_name = 'pages_domains'
        indexes = (
            (('domain', 'wildcard'), True),
            (('project', 'enabled_until'), False),
            (('verified_at', 'enabled_until'), False),
        )

class PagesDomainAcmeOrders(BaseModel):
    challenge_file_content = TextField()
    challenge_token = CharField(index=True)
    created_at = DateTimeField()
    encrypted_private_key = TextField()
    encrypted_private_key_iv = TextField()
    expires_at = DateTimeField()
    id = BigAutoField()
    pages_domain = ForeignKeyField(column_name='pages_domain_id', field='id', model=PagesDomains)
    updated_at = DateTimeField()
    url = CharField()

    class Meta:
        table_name = 'pages_domain_acme_orders'

class PartitionedForeignKeys(BaseModel):
    cascade_delete = BooleanField(constraints=[SQL("DEFAULT true")])
    from_column = TextField()
    from_table = TextField()
    id = BigAutoField()
    to_column = TextField()
    to_table = TextField()

    class Meta:
        table_name = 'partitioned_foreign_keys'
        indexes = (
            (('to_table', 'from_table', 'from_column'), True),
        )

class PathLocks(BaseModel):
    created_at = DateTimeField()
    path = CharField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'path_locks'

class PersonalAccessTokens(BaseModel):
    after_expiry_notification_delivered = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    expire_notification_delivered = BooleanField(constraints=[SQL("DEFAULT false")])
    expires_at = DateField(null=True)
    impersonation = BooleanField(constraints=[SQL("DEFAULT false")])
    last_used_at = DateTimeField(null=True)
    name = CharField()
    revoked = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    scopes = CharField(constraints=[SQL("DEFAULT '--- []\n'::character varying")])
    token_digest = CharField(null=True, unique=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'personal_access_tokens'
        indexes = (
            (('id', 'expires_at'), False),
            (('user', 'expires_at'), False),
        )

class PlanLimits(BaseModel):
    ci_active_jobs = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_active_pipelines = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_instance_level_variables = IntegerField(constraints=[SQL("DEFAULT 25")])
    ci_max_artifact_size_accessibility = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_api_fuzzing = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_archive = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_browser_performance = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_cluster_applications = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_cobertura = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_codequality = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_container_scanning = IntegerField(constraints=[SQL("DEFAULT 150")])
    ci_max_artifact_size_coverage_fuzzing = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_dast = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_dependency_scanning = IntegerField(constraints=[SQL("DEFAULT 350")])
    ci_max_artifact_size_dotenv = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_junit = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_license_management = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_license_scanning = IntegerField(constraints=[SQL("DEFAULT 100")])
    ci_max_artifact_size_load_performance = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_lsif = IntegerField(constraints=[SQL("DEFAULT 100")])
    ci_max_artifact_size_metadata = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_metrics = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_metrics_referee = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_network_referee = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_performance = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_requirements = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_sast = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_secret_detection = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_max_artifact_size_terraform = IntegerField(constraints=[SQL("DEFAULT 5")])
    ci_max_artifact_size_trace = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_needs_size_limit = IntegerField(constraints=[SQL("DEFAULT 50")])
    ci_pipeline_schedules = IntegerField(constraints=[SQL("DEFAULT 10")])
    ci_pipeline_size = IntegerField(constraints=[SQL("DEFAULT 0")])
    ci_project_subscriptions = IntegerField(constraints=[SQL("DEFAULT 2")])
    conan_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT '3221225472'::bigint")])
    debian_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT '3221225472'::bigint")])
    generic_packages_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT '5368709120'::bigint")])
    golang_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT 104857600")])
    group_hooks = IntegerField(constraints=[SQL("DEFAULT 50")])
    id = BigAutoField()
    maven_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT '3221225472'::bigint")])
    npm_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT 524288000")])
    nuget_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT 524288000")])
    offset_pagination_limit = IntegerField(constraints=[SQL("DEFAULT 50000")])
    plan = ForeignKeyField(column_name='plan_id', field='id', model=Plans, unique=True)
    project_feature_flags = IntegerField(constraints=[SQL("DEFAULT 200")])
    project_hooks = IntegerField(constraints=[SQL("DEFAULT 100")])
    pypi_max_file_size = BigIntegerField(constraints=[SQL("DEFAULT '3221225472'::bigint")])
    storage_size_limit = IntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'plan_limits'

class PostgresReindexActions(BaseModel):
    action_end = DateTimeField(null=True)
    action_start = DateTimeField()
    id = BigAutoField()
    index_identifier = TextField(index=True)
    ondisk_size_bytes_end = BigIntegerField(null=True)
    ondisk_size_bytes_start = BigIntegerField()
    state = SmallIntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'postgres_reindex_actions'

class ProductAnalyticsEventsExperimental(BaseModel):
    base_currency = CharField(null=True)
    br_colordepth = CharField(null=True)
    br_cookies = BooleanField(null=True)
    br_family = CharField(null=True)
    br_features_director = BooleanField(null=True)
    br_features_flash = BooleanField(null=True)
    br_features_gears = BooleanField(null=True)
    br_features_java = BooleanField(null=True)
    br_features_pdf = BooleanField(null=True)
    br_features_quicktime = BooleanField(null=True)
    br_features_realplayer = BooleanField(null=True)
    br_features_silverlight = BooleanField(null=True)
    br_features_windowsmedia = BooleanField(null=True)
    br_lang = CharField(null=True)
    br_name = CharField(null=True)
    br_renderengine = CharField(null=True)
    br_type = CharField(null=True)
    br_version = CharField(null=True)
    br_viewheight = IntegerField(null=True)
    br_viewwidth = IntegerField(null=True)
    collector_tstamp = DateTimeField()
    derived_tstamp = DateTimeField(null=True)
    doc_charset = CharField(null=True)
    doc_height = IntegerField(null=True)
    doc_width = IntegerField(null=True)
    domain_sessionid = CharField(null=True)
    domain_sessionidx = SmallIntegerField(null=True)
    domain_userid = CharField(null=True)
    dvce_created_tstamp = DateTimeField(null=True)
    dvce_ismobile = BooleanField(null=True)
    dvce_screenheight = IntegerField(null=True)
    dvce_screenwidth = IntegerField(null=True)
    dvce_sent_tstamp = DateTimeField(null=True)
    dvce_type = CharField(null=True)
    etl_tags = CharField(null=True)
    etl_tstamp = DateTimeField(null=True)
    event = CharField(null=True)
    event_fingerprint = CharField(null=True)
    event_format = CharField(null=True)
    event_id = CharField()
    event_name = CharField(null=True)
    event_vendor = CharField(null=True)
    event_version = CharField(null=True)
    geo_city = CharField(null=True)
    geo_country = CharField(null=True)
    geo_latitude = DoubleField(null=True)
    geo_longitude = DoubleField(null=True)
    geo_region = CharField(null=True)
    geo_region_name = CharField(null=True)
    geo_timezone = CharField(null=True)
    geo_zipcode = CharField(null=True)
    id = BigIntegerField(constraints=[SQL("DEFAULT nextval('product_analytics_events_experimental_id_seq'::regclass)")])
    ip_domain = CharField(null=True)
    ip_isp = CharField(null=True)
    ip_netspeed = CharField(null=True)
    ip_organization = CharField(null=True)
    mkt_campaign = CharField(null=True)
    mkt_clickid = CharField(null=True)
    mkt_content = CharField(null=True)
    mkt_medium = CharField(null=True)
    mkt_network = CharField(null=True)
    mkt_source = CharField(null=True)
    mkt_term = CharField(null=True)
    name_tracker = CharField(null=True)
    network_userid = CharField(null=True)
    os_family = CharField(null=True)
    os_manufacturer = CharField(null=True)
    os_name = CharField(null=True)
    os_timezone = CharField(null=True)
    page_referrer = TextField(null=True)
    page_title = CharField(null=True)
    page_url = TextField(null=True)
    page_urlfragment = CharField(null=True)
    page_urlhost = CharField(null=True)
    page_urlpath = CharField(null=True)
    page_urlport = IntegerField(null=True)
    page_urlquery = CharField(null=True)
    page_urlscheme = CharField(null=True)
    platform = CharField(null=True)
    pp_xoffset_max = IntegerField(null=True)
    pp_xoffset_min = IntegerField(null=True)
    pp_yoffset_max = IntegerField(null=True)
    pp_yoffset_min = IntegerField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    refr_domain_userid = CharField(null=True)
    refr_dvce_tstamp = DateTimeField(null=True)
    refr_medium = CharField(null=True)
    refr_source = CharField(null=True)
    refr_term = CharField(null=True)
    refr_urlfragment = CharField(null=True)
    refr_urlhost = CharField(null=True)
    refr_urlpath = CharField(null=True)
    refr_urlport = IntegerField(null=True)
    refr_urlquery = CharField(null=True)
    refr_urlscheme = CharField(null=True)
    se_action = CharField(null=True)
    se_category = CharField(null=True)
    se_label = CharField(null=True)
    se_property = CharField(null=True)
    se_value = DoubleField(null=True)
    ti_category = CharField(null=True)
    ti_currency = CharField(null=True)
    ti_name = CharField(null=True)
    ti_orderid = CharField(null=True)
    ti_price = DecimalField(null=True)
    ti_price_base = DecimalField(null=True)
    ti_quantity = IntegerField(null=True)
    ti_sku = CharField(null=True)
    tr_affiliation = CharField(null=True)
    tr_city = CharField(null=True)
    tr_country = CharField(null=True)
    tr_currency = CharField(null=True)
    tr_orderid = CharField(null=True)
    tr_shipping = DecimalField(null=True)
    tr_shipping_base = DecimalField(null=True)
    tr_state = CharField(null=True)
    tr_tax = DecimalField(null=True)
    tr_tax_base = DecimalField(null=True)
    tr_total = DecimalField(null=True)
    tr_total_base = DecimalField(null=True)
    true_tstamp = DateTimeField(null=True)
    txn_id = IntegerField(null=True)
    user_fingerprint = CharField(null=True)
    user_id = CharField(null=True)
    user_ipaddress = CharField(null=True)
    useragent = CharField(null=True)
    v_collector = CharField()
    v_etl = CharField()
    v_tracker = CharField(null=True)

    class Meta:
        table_name = 'product_analytics_events_experimental'
        primary_key = CompositeKey('id', 'project')

class ProjectAccessTokens(BaseModel):
    personal_access_token = ForeignKeyField(column_name='personal_access_token_id', field='id', model=PersonalAccessTokens)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'project_access_tokens'
        indexes = (
            (('personal_access_token', 'project'), True),
        )
        primary_key = CompositeKey('personal_access_token', 'project')

class ProjectAlertingSettings(BaseModel):
    encrypted_token = CharField()
    encrypted_token_iv = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)

    class Meta:
        table_name = 'project_alerting_settings'

class ProjectAliases(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    name = CharField(unique=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_aliases'

class ProjectAuthorizations(BaseModel):
    access_level = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'project_authorizations'
        indexes = (
            (('user', 'project', 'access_level'), True),
        )
        primary_key = CompositeKey('access_level', 'project', 'user')

class ProjectAutoDevops(BaseModel):
    created_at = DateTimeField()
    deploy_strategy = IntegerField(constraints=[SQL("DEFAULT 0")])
    enabled = BooleanField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_auto_devops'

class ProjectCiCdSettings(BaseModel):
    auto_rollback_enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    default_git_depth = IntegerField(null=True)
    forward_deployment_enabled = BooleanField(null=True)
    group_runners_enabled = BooleanField(constraints=[SQL("DEFAULT true")])
    merge_pipelines_enabled = BooleanField(null=True)
    merge_trains_enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)

    class Meta:
        table_name = 'project_ci_cd_settings'

class ProjectComplianceFrameworkSettings(BaseModel):
    framework = SmallIntegerField(null=True)
    framework_id = ForeignKeyField(column_name='framework_id', field='id', model=ComplianceManagementFrameworks, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)

    class Meta:
        table_name = 'project_compliance_framework_settings'

class ProjectCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    value = CharField()

    class Meta:
        table_name = 'project_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('project', 'key'), True),
        )

class ProjectDailyStatistics(BaseModel):
    date = DateField(null=True)
    fetch_count = IntegerField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'project_daily_statistics'
        indexes = (
            (('project', 'date'), True),
        )

class ProjectDeployTokens(BaseModel):
    created_at = DateTimeField()
    deploy_token = ForeignKeyField(column_name='deploy_token_id', field='id', model=DeployTokens)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)

    class Meta:
        table_name = 'project_deploy_tokens'
        indexes = (
            (('project', 'deploy_token'), True),
        )

class ProjectErrorTrackingSettings(BaseModel):
    api_url = CharField(null=True)
    enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    encrypted_token = CharField(null=True)
    encrypted_token_iv = CharField(null=True)
    organization_name = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    project_name = CharField(null=True)

    class Meta:
        table_name = 'project_error_tracking_settings'

class ProjectExportJobs(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    jid = CharField(unique=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    status = SmallIntegerField(constraints=[SQL("DEFAULT 0")], index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_export_jobs'
        indexes = (
            (('project', 'jid'), False),
            (('project', 'status'), False),
        )

class ProjectFeatureUsages(BaseModel):
    jira_dvcs_cloud_last_sync_at = DateTimeField(null=True)
    jira_dvcs_server_last_sync_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)

    class Meta:
        table_name = 'project_feature_usages'
        indexes = (
            (('jira_dvcs_cloud_last_sync_at', 'project'), False),
            (('jira_dvcs_server_last_sync_at', 'project'), False),
        )

class ProjectFeatures(BaseModel):
    builds_access_level = IntegerField(null=True)
    created_at = DateTimeField(null=True)
    forking_access_level = IntegerField(null=True)
    issues_access_level = IntegerField(null=True)
    merge_requests_access_level = IntegerField(null=True)
    metrics_dashboard_access_level = IntegerField(null=True)
    pages_access_level = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    repository_access_level = IntegerField(constraints=[SQL("DEFAULT 20")])
    requirements_access_level = IntegerField(constraints=[SQL("DEFAULT 20")])
    snippets_access_level = IntegerField(constraints=[SQL("DEFAULT 20")])
    updated_at = DateTimeField(null=True)
    wiki_access_level = IntegerField(null=True)

    class Meta:
        table_name = 'project_features'

class ProjectGroupLinks(BaseModel):
    created_at = DateTimeField(null=True)
    expires_at = DateField(null=True)
    group_access = IntegerField(constraints=[SQL("DEFAULT 30")])
    group_id = IntegerField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'project_group_links'

class ProjectImportData(BaseModel):
    data = TextField(null=True)
    encrypted_credentials = TextField(null=True)
    encrypted_credentials_iv = CharField(null=True)
    encrypted_credentials_salt = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)

    class Meta:
        table_name = 'project_import_data'

class ProjectIncidentManagementSettings(BaseModel):
    auto_close_incident = BooleanField(constraints=[SQL("DEFAULT true")])
    create_issue = BooleanField(constraints=[SQL("DEFAULT false")])
    encrypted_pagerduty_token = BlobField(null=True)
    encrypted_pagerduty_token_iv = BlobField(null=True)
    issue_template_key = TextField(null=True)
    pagerduty_active = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    send_email = BooleanField(constraints=[SQL("DEFAULT false")])
    sla_timer = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    sla_timer_minutes = IntegerField(null=True)

    class Meta:
        table_name = 'project_incident_management_settings'

class ProjectMetricsSettings(BaseModel):
    dashboard_timezone = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    external_dashboard_url = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)

    class Meta:
        table_name = 'project_metrics_settings'

class ProjectMirrorData(BaseModel):
    correlation_id_value = CharField(null=True)
    jid = CharField(null=True)
    last_error = TextField(null=True)
    last_successful_update_at = DateTimeField(index=True, null=True)
    last_update_at = DateTimeField(null=True)
    last_update_scheduled_at = DateTimeField(null=True)
    last_update_started_at = DateTimeField(null=True)
    next_execution_timestamp = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    retry_count = IntegerField(constraints=[SQL("DEFAULT 0")])
    status = CharField(index=True, null=True)

    class Meta:
        table_name = 'project_mirror_data'
        indexes = (
            (('last_update_at', 'retry_count'), False),
            (('next_execution_timestamp', 'retry_count'), False),
        )

class ProjectPagesMetadata(BaseModel):
    artifacts_archive = ForeignKeyField(column_name='artifacts_archive_id', field='id', model=CiJobArtifacts, null=True)
    deployed = BooleanField(constraints=[SQL("DEFAULT false")])
    pages_deployment = ForeignKeyField(column_name='pages_deployment_id', field='id', model=PagesDeployments, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)

    class Meta:
        table_name = 'project_pages_metadata'

class ProjectRepositories(BaseModel):
    disk_path = CharField(unique=True)
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    shard = ForeignKeyField(column_name='shard_id', field='id', model=Shards)

    class Meta:
        table_name = 'project_repositories'

class ProjectRepositoryStates(BaseModel):
    last_repository_verification_failure = CharField(index=True, null=True)
    last_repository_verification_ran_at = DateTimeField(null=True)
    last_wiki_verification_failure = CharField(index=True, null=True)
    last_wiki_verification_ran_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    repository_retry_at = DateTimeField(null=True)
    repository_retry_count = IntegerField(null=True)
    repository_verification_checksum = BlobField(null=True)
    wiki_retry_at = DateTimeField(null=True)
    wiki_retry_count = IntegerField(null=True)
    wiki_verification_checksum = BlobField(null=True)

    class Meta:
        table_name = 'project_repository_states'
        indexes = (
            (('project', 'last_repository_verification_ran_at'), False),
            (('project', 'last_wiki_verification_ran_at'), False),
        )

class ProjectRepositoryStorageMoves(BaseModel):
    created_at = DateTimeField()
    destination_storage_name = TextField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    source_storage_name = TextField()
    state = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_repository_storage_moves'

class ProjectSecuritySettings(BaseModel):
    auto_fix_container_scanning = BooleanField(constraints=[SQL("DEFAULT true")])
    auto_fix_dast = BooleanField(constraints=[SQL("DEFAULT true")])
    auto_fix_dependency_scanning = BooleanField(constraints=[SQL("DEFAULT true")])
    auto_fix_sast = BooleanField(constraints=[SQL("DEFAULT true")])
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_security_settings'

class ProjectSettings(BaseModel):
    allow_merge_on_skipped_pipeline = BooleanField(null=True)
    created_at = DateTimeField()
    has_confluence = BooleanField(constraints=[SQL("DEFAULT false")])
    has_vulnerabilities = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    push_rule = ForeignKeyField(column_name='push_rule_id', field='id', model=PushRules, null=True, unique=True)
    show_default_award_emojis = BooleanField(constraints=[SQL("DEFAULT true")])
    squash_option = SmallIntegerField(constraints=[SQL("DEFAULT 3")], null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_settings'

class ProjectStatistics(BaseModel):
    build_artifacts_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    commit_count = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    lfs_objects_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    namespace_id = IntegerField(index=True)
    packages_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    pipeline_artifacts_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    repository_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    shared_runners_seconds = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    shared_runners_seconds_last_reset = DateTimeField(null=True)
    snippets_size = BigIntegerField(null=True)
    storage_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    uploads_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    wiki_size = BigIntegerField(null=True)

    class Meta:
        table_name = 'project_statistics'
        indexes = (
            (('repository_size', 'project'), False),
            (('storage_size', 'project'), False),
            (('wiki_size', 'project'), False),
        )

class ProjectTracingSettings(BaseModel):
    created_at = DateTimeField()
    external_url = CharField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'project_tracing_settings'

class ProtectedBranchMergeAccessLevels(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 40")], null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_branch_merge_access_levels'

class ProtectedBranchPushAccessLevels(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 40")], null=True)
    created_at = DateTimeField()
    deploy_key = ForeignKeyField(column_name='deploy_key_id', field='id', model=Keys, null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_branch_push_access_levels'

class ProtectedBranchUnprotectAccessLevels(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 40")], null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_branch_unprotect_access_levels'

class ProtectedEnvironments(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'protected_environments'
        indexes = (
            (('project', 'name'), True),
        )

class ProtectedEnvironmentDeployAccessLevels(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 40")], null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_environment = ForeignKeyField(column_name='protected_environment_id', field='id', model=ProtectedEnvironments)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_environment_deploy_access_levels'

class ProtectedTags(BaseModel):
    created_at = DateTimeField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'protected_tags'
        indexes = (
            (('project', 'name'), True),
        )

class ProtectedTagCreateAccessLevels(BaseModel):
    access_level = IntegerField(constraints=[SQL("DEFAULT 40")], null=True)
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    protected_tag = ForeignKeyField(column_name='protected_tag_id', field='id', model=ProtectedTags)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'protected_tag_create_access_levels'

class PushEventPayloads(BaseModel):
    action = SmallIntegerField()
    commit_count = BigIntegerField()
    commit_from = BlobField(null=True)
    commit_title = CharField(null=True)
    commit_to = BlobField(null=True)
    event = ForeignKeyField(column_name='event_id', field='id', model=Events, primary_key=True)
    ref = TextField(null=True)
    ref_count = IntegerField(null=True)
    ref_type = SmallIntegerField()

    class Meta:
        table_name = 'push_event_payloads'

class RawUsageData(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    payload = BinaryJSONField()
    recorded_at = DateTimeField(unique=True)
    sent_at = DateTimeField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'raw_usage_data'

class RedirectRoutes(BaseModel):
    created_at = DateTimeField()
    path = CharField(unique=True)
    source_id = IntegerField()
    source_type = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'redirect_routes'
        indexes = (
            (('source_type', 'source_id'), False),
        )

class ReleaseLinks(BaseModel):
    created_at = DateTimeField()
    filepath = CharField(null=True)
    id = BigAutoField()
    link_type = SmallIntegerField(constraints=[SQL("DEFAULT 0")], null=True)
    name = CharField()
    release = ForeignKeyField(column_name='release_id', field='id', model=Releases)
    updated_at = DateTimeField()
    url = CharField()

    class Meta:
        table_name = 'release_links'
        indexes = (
            (('release', 'name'), True),
            (('release', 'url'), True),
        )

class RemoteMirrors(BaseModel):
    created_at = DateTimeField()
    enabled = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    encrypted_credentials = TextField(null=True)
    encrypted_credentials_iv = CharField(null=True)
    encrypted_credentials_salt = CharField(null=True)
    error_notification_sent = BooleanField(null=True)
    keep_divergent_refs = BooleanField(null=True)
    last_error = CharField(null=True)
    last_successful_update_at = DateTimeField(index=True, null=True)
    last_update_at = DateTimeField(null=True)
    last_update_started_at = DateTimeField(null=True)
    only_protected_branches = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    remote_name = CharField(null=True)
    update_status = CharField(null=True)
    updated_at = DateTimeField()
    url = CharField(null=True)

    class Meta:
        table_name = 'remote_mirrors'

class RepositoryLanguages(BaseModel):
    programming_language_id = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    share = DoubleField()

    class Meta:
        table_name = 'repository_languages'
        indexes = (
            (('project', 'programming_language_id'), True),
        )
        primary_key = CompositeKey('programming_language_id', 'project')

class RequiredCodeOwnersSections(BaseModel):
    id = BigAutoField()
    name = TextField()
    protected_branch = ForeignKeyField(column_name='protected_branch_id', field='id', model=ProtectedBranches)

    class Meta:
        table_name = 'required_code_owners_sections'

class Requirements(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField(index=True)
    description = TextField(null=True)
    description_html = TextField(null=True)
    id = BigAutoField()
    iid = IntegerField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    state = SmallIntegerField(constraints=[SQL("DEFAULT 1")], index=True)
    title = CharField(index=True)
    title_html = TextField(null=True)
    updated_at = DateTimeField(index=True)

    class Meta:
        table_name = 'requirements'
        indexes = (
            (('project', 'iid'), True),
        )

class RequirementsManagementTestReports(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users, null=True)
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds, null=True)
    created_at = DateTimeField()
    id = BigAutoField()
    requirement = ForeignKeyField(column_name='requirement_id', field='id', model=Requirements)
    state = SmallIntegerField()

    class Meta:
        table_name = 'requirements_management_test_reports'

class ResourceIterationEvents(BaseModel):
    action = SmallIntegerField()
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    iteration = ForeignKeyField(column_name='iteration_id', field='id', model=Sprints, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'resource_iteration_events'

class ResourceLabelEvents(BaseModel):
    action = IntegerField()
    cached_markdown_version = IntegerField(null=True)
    created_at = DateTimeField()
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics, null=True)
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    label = ForeignKeyField(column_name='label_id', field='id', model=Labels, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    reference = TextField(null=True)
    reference_html = TextField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'resource_label_events'
        indexes = (
            (('issue', 'label', 'action'), False),
            (('label', 'action'), False),
            (('merge_request', 'label', 'action'), False),
        )

class ResourceMilestoneEvents(BaseModel):
    action = SmallIntegerField()
    created_at = DateTimeField(index=True)
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    milestone = ForeignKeyField(column_name='milestone_id', field='id', model=Milestones, null=True)
    state = SmallIntegerField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'resource_milestone_events'

class ResourceStateEvents(BaseModel):
    close_after_error_tracking_resolve = BooleanField(constraints=[SQL("DEFAULT false")])
    close_auto_resolve_prometheus_alert = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics, null=True)
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    source_commit = TextField(null=True)
    source_merge_request = ForeignKeyField(backref='merge_requests_source_merge_request_set', column_name='source_merge_request_id', field='id', model=MergeRequests, null=True)
    state = SmallIntegerField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'resource_state_events'
        indexes = (
            (('issue', 'created_at'), False),
        )

class ResourceWeightEvents(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)
    weight = IntegerField(null=True)

    class Meta:
        table_name = 'resource_weight_events'
        indexes = (
            (('issue', 'created_at'), False),
            (('issue', 'weight'), False),
        )

class Routes(BaseModel):
    created_at = DateTimeField(null=True)
    name = CharField(index=True, null=True)
    path = CharField(index=True)
    source_id = IntegerField()
    source_type = CharField()
    updated_at = DateTimeField(null=True)

    class Meta:
        table_name = 'routes'
        indexes = (
            (('source_type', 'source_id'), True),
        )

class SamlGroupLinks(BaseModel):
    access_level = SmallIntegerField()
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    saml_group_name = TextField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'saml_group_links'
        indexes = (
            (('group', 'saml_group_name'), True),
        )

class SchemaMigrations(BaseModel):
    version = CharField(unique=True)

    class Meta:
        table_name = 'schema_migrations'
        primary_key = False

class ScimIdentities(BaseModel):
    active = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    created_at = DateTimeField()
    extern_uid = CharField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    id = BigAutoField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'scim_identities'
        indexes = (
            (('group'), True),
            (('user', 'group'), True),
        )

class ScimOauthAccessTokens(BaseModel):
    created_at = DateTimeField()
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces)
    token_encrypted = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'scim_oauth_access_tokens'
        indexes = (
            (('group', 'token_encrypted'), True),
        )

class SecurityScans(BaseModel):
    build = ForeignKeyField(column_name='build_id', field='id', model=CiBuilds)
    created_at = DateTimeField()
    id = BigAutoField()
    scan_type = SmallIntegerField(index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'security_scans'
        indexes = (
            (('build', 'scan_type'), True),
        )

class VulnerabilityScanners(BaseModel):
    created_at = DateTimeField()
    external_id = CharField()
    id = BigAutoField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    vendor = TextField(constraints=[SQL("DEFAULT 'GitLab'::text")])

    class Meta:
        table_name = 'vulnerability_scanners'
        indexes = (
            (('project', 'external_id'), True),
        )

class SecurityFindings(BaseModel):
    confidence = SmallIntegerField(index=True)
    deduplicated = BooleanField(constraints=[SQL("DEFAULT false")])
    id = BigAutoField()
    position = IntegerField(null=True)
    project_fingerprint = TextField(index=True)
    scan = ForeignKeyField(column_name='scan_id', field='id', model=SecurityScans)
    scanner = ForeignKeyField(column_name='scanner_id', field='id', model=VulnerabilityScanners)
    severity = SmallIntegerField(index=True)

    class Meta:
        table_name = 'security_findings'
        indexes = (
            (('scan'), True),
            (('scan', 'deduplicated'), False),
        )

class SentNotifications(BaseModel):
    commit_id = CharField(null=True)
    in_reply_to_discussion_id = CharField(null=True)
    line_code = CharField(null=True)
    note_type = CharField(null=True)
    noteable_id = IntegerField(index=True, null=True)
    noteable_type = CharField(null=True)
    position = TextField(null=True)
    project_id = IntegerField(null=True)
    recipient_id = IntegerField(null=True)
    reply_key = CharField(unique=True)

    class Meta:
        table_name = 'sent_notifications'

class SentryIssues(BaseModel):
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)
    sentry_issue_identifier = BigIntegerField(index=True)

    class Meta:
        table_name = 'sentry_issues'

class ServerlessDomainCluster(BaseModel):
    certificate = TextField(null=True)
    clusters_applications_knative = ForeignKeyField(column_name='clusters_applications_knative_id', field='id', model=ClustersApplicationsKnative, unique=True)
    created_at = DateTimeField()
    creator = ForeignKeyField(column_name='creator_id', field='id', model=Users, null=True)
    encrypted_key = TextField(null=True)
    encrypted_key_iv = CharField(null=True)
    pages_domain = ForeignKeyField(column_name='pages_domain_id', field='id', model=PagesDomains)
    updated_at = DateTimeField()
    uuid = CharField(primary_key=True)

    class Meta:
        table_name = 'serverless_domain_cluster'

class ServiceDeskSettings(BaseModel):
    issue_template_key = CharField(null=True)
    outgoing_name = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    project_key = CharField(null=True)

    class Meta:
        table_name = 'service_desk_settings'

class SlackIntegrations(BaseModel):
    alias = CharField()
    created_at = DateTimeField()
    service = ForeignKeyField(column_name='service_id', field='id', model=Services)
    team_id = CharField()
    team_name = CharField()
    updated_at = DateTimeField()
    user_id = CharField()

    class Meta:
        table_name = 'slack_integrations'
        indexes = (
            (('team_id', 'alias'), True),
        )

class SmartcardIdentities(BaseModel):
    id = BigAutoField()
    issuer = CharField()
    subject = CharField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'smartcard_identities'
        indexes = (
            (('subject', 'issuer'), True),
        )

class Snippets(BaseModel):
    author_id = IntegerField(index=True)
    cached_markdown_version = IntegerField(null=True)
    content = TextField(index=True, null=True)
    content_html = TextField(null=True)
    created_at = DateTimeField(index=True, null=True)
    description = TextField(index=True, null=True)
    description_html = TextField(null=True)
    encrypted_secret_token = CharField(null=True)
    encrypted_secret_token_iv = CharField(null=True)
    file_name = CharField(index=True, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    repository_read_only = BooleanField(constraints=[SQL("DEFAULT false")])
    secret = BooleanField(constraints=[SQL("DEFAULT false")])
    title = CharField(index=True, null=True)
    title_html = TextField(null=True)
    type = CharField(null=True)
    updated_at = DateTimeField(index=True, null=True)
    visibility_level = IntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'snippets'
        indexes = (
            (('id', 'created_at'), False),
            (('id', 'type'), False),
            (('project', 'visibility_level'), False),
            (('visibility_level', 'secret'), False),
        )

class SnippetRepositories(BaseModel):
    disk_path = CharField(unique=True)
    shard = ForeignKeyField(column_name='shard_id', field='id', model=Shards)
    snippet = ForeignKeyField(column_name='snippet_id', field='id', model=Snippets, primary_key=True)
    verification_checksum = BlobField(index=True, null=True)
    verification_failure = TextField(index=True, null=True)
    verification_retry_at = DateTimeField(null=True)
    verification_retry_count = SmallIntegerField(null=True)
    verified_at = DateTimeField(null=True)

    class Meta:
        table_name = 'snippet_repositories'

class SnippetRepositoryStorageMoves(BaseModel):
    created_at = DateTimeField()
    destination_storage_name = TextField()
    id = BigAutoField()
    snippet = ForeignKeyField(column_name='snippet_id', field='id', model=Snippets)
    source_storage_name = TextField()
    state = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'snippet_repository_storage_moves'

class SnippetStatistics(BaseModel):
    commit_count = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    file_count = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    repository_size = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    snippet = ForeignKeyField(column_name='snippet_id', field='id', model=Snippets, primary_key=True)

    class Meta:
        table_name = 'snippet_statistics'

class SnippetUserMentions(BaseModel):
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)
    snippet = ForeignKeyField(column_name='snippet_id', field='id', model=Snippets, unique=True)

    class Meta:
        table_name = 'snippet_user_mentions'
        indexes = (
            (('snippet', 'note'), True),
        )

class SoftwareLicenses(BaseModel):
    name = CharField(unique=True)
    spdx_identifier = CharField(index=True, null=True)

    class Meta:
        table_name = 'software_licenses'

class SoftwareLicensePolicies(BaseModel):
    classification = IntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    software_license = ForeignKeyField(column_name='software_license_id', field='id', model=SoftwareLicenses)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'software_license_policies'
        indexes = (
            (('project', 'software_license'), True),
        )

class SpamLogs(BaseModel):
    created_at = DateTimeField()
    description = TextField(null=True)
    noteable_type = CharField(null=True)
    recaptcha_verified = BooleanField(constraints=[SQL("DEFAULT false")])
    source_ip = CharField(null=True)
    submitted_as_ham = BooleanField(constraints=[SQL("DEFAULT false")])
    title = CharField(null=True)
    updated_at = DateTimeField()
    user_agent = CharField(null=True)
    user_id = IntegerField(null=True)
    via_api = BooleanField(null=True)

    class Meta:
        table_name = 'spam_logs'

class StatusPagePublishedIncidents(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'status_page_published_incidents'

class StatusPageSettings(BaseModel):
    aws_access_key = CharField()
    aws_region = CharField()
    aws_s3_bucket_name = CharField()
    created_at = DateTimeField()
    enabled = BooleanField(constraints=[SQL("DEFAULT false")])
    encrypted_aws_secret_key = CharField()
    encrypted_aws_secret_key_iv = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, primary_key=True)
    status_page_url = TextField(null=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'status_page_settings'

class Subscriptions(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    subscribable_id = IntegerField(null=True)
    subscribable_type = CharField(null=True)
    subscribed = BooleanField(null=True)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField(null=True)

    class Meta:
        table_name = 'subscriptions'
        indexes = (
            (('subscribable_id', 'subscribable_type', 'user_id', 'project'), True),
        )

class Suggestions(BaseModel):
    applied = BooleanField(constraints=[SQL("DEFAULT false")])
    commit_id = CharField(null=True)
    from_content = TextField()
    id = BigAutoField()
    lines_above = IntegerField(constraints=[SQL("DEFAULT 0")])
    lines_below = IntegerField(constraints=[SQL("DEFAULT 0")])
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes)
    outdated = BooleanField(constraints=[SQL("DEFAULT false")])
    relative_order = SmallIntegerField()
    to_content = TextField()

    class Meta:
        table_name = 'suggestions'
        indexes = (
            (('note', 'relative_order'), True),
        )

class SystemNoteMetadata(BaseModel):
    action = CharField(null=True)
    commit_count = IntegerField(null=True)
    created_at = DateTimeField()
    description_version = ForeignKeyField(column_name='description_version_id', field='id', model=DescriptionVersions, null=True, unique=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, unique=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'system_note_metadata'

class Taggings(BaseModel):
    context = CharField(null=True)
    created_at = DateTimeField(null=True)
    tag_id = IntegerField(index=True, null=True)
    taggable_id = IntegerField(null=True)
    taggable_type = CharField(null=True)
    tagger_id = IntegerField(null=True)
    tagger_type = CharField(null=True)

    class Meta:
        table_name = 'taggings'
        indexes = (
            (('tag_id', 'taggable_id', 'taggable_type', 'context', 'tagger_id', 'tagger_type'), True),
            (('taggable_id', 'taggable_type'), False),
            (('taggable_id', 'taggable_type', 'context'), False),
        )

class Tags(BaseModel):
    name = CharField(index=True, null=True)
    taggings_count = IntegerField(constraints=[SQL("DEFAULT 0")], null=True)

    class Meta:
        table_name = 'tags'

class TermAgreements(BaseModel):
    accepted = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    term = ForeignKeyField(column_name='term_id', field='id', model=ApplicationSettingTerms)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'term_agreements'
        indexes = (
            (('user', 'term'), True),
        )

class TerraformStates(BaseModel):
    created_at = DateTimeField()
    file = CharField(null=True)
    file_store = SmallIntegerField(index=True, null=True)
    id = BigAutoField()
    lock_xid = CharField(null=True)
    locked_at = DateTimeField(null=True)
    locked_by_user = ForeignKeyField(column_name='locked_by_user_id', field='id', model=Users, null=True)
    name = CharField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    uuid = CharField(unique=True)
    versioning_enabled = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'terraform_states'
        indexes = (
            (('project', 'name'), True),
        )

class TerraformStateVersions(BaseModel):
    ci_build = ForeignKeyField(column_name='ci_build_id', field='id', model=CiBuilds, null=True)
    created_at = DateTimeField()
    created_by_user = ForeignKeyField(column_name='created_by_user_id', field='id', model=Users, null=True)
    file = TextField()
    file_store = SmallIntegerField()
    id = BigAutoField()
    terraform_state = ForeignKeyField(column_name='terraform_state_id', field='id', model=TerraformStates)
    updated_at = DateTimeField()
    verification_checksum = BlobField(index=True, null=True)
    verification_failure = TextField(index=True, null=True)
    verification_retry_at = DateTimeField(null=True)
    verification_retry_count = SmallIntegerField(null=True)
    verified_at = DateTimeField(null=True)
    version = IntegerField()

    class Meta:
        table_name = 'terraform_state_versions'
        indexes = (
            (('terraform_state', 'version'), True),
        )

class Timelogs(BaseModel):
    created_at = DateTimeField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True)
    spent_at = DateTimeField(index=True, null=True)
    time_spent = IntegerField()
    updated_at = DateTimeField()
    user_id = IntegerField(index=True, null=True)

    class Meta:
        table_name = 'timelogs'

class Todos(BaseModel):
    action = IntegerField()
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    commit_id = CharField(index=True, null=True)
    created_at = DateTimeField(null=True)
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    resolved_by_action = SmallIntegerField(null=True)
    state = CharField()
    target_id = IntegerField(null=True)
    target_type = CharField()
    updated_at = DateTimeField(null=True)
    user = ForeignKeyField(backref='users_user_set', column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'todos'
        indexes = (
            (('author', 'created_at'), False),
            (('target_type', 'target_id'), False),
            (('user', 'id'), False),
            (('user', 'id'), False),
        )

class TrendingProjects(BaseModel):
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)

    class Meta:
        table_name = 'trending_projects'

class U2FRegistrations(BaseModel):
    certificate = TextField(null=True)
    counter = IntegerField(null=True)
    created_at = DateTimeField()
    key_handle = CharField(index=True, null=True)
    name = CharField(null=True)
    public_key = CharField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'u2f_registrations'

class Uploads(BaseModel):
    checksum = CharField(index=True, null=True)
    created_at = DateTimeField()
    model_id = IntegerField(null=True)
    model_type = CharField(null=True)
    mount_point = CharField(null=True)
    path = CharField()
    secret = CharField(null=True)
    size = BigIntegerField()
    store = IntegerField(constraints=[SQL("DEFAULT 1")], index=True, null=True)
    uploader = CharField()

    class Meta:
        table_name = 'uploads'
        indexes = (
            (('model_id', 'model_type'), False),
            (('uploader', 'path'), False),
        )

class UserAgentDetails(BaseModel):
    created_at = DateTimeField()
    ip_address = CharField()
    subject_id = IntegerField()
    subject_type = CharField()
    submitted = BooleanField(constraints=[SQL("DEFAULT false")])
    updated_at = DateTimeField()
    user_agent = CharField()

    class Meta:
        table_name = 'user_agent_details'
        indexes = (
            (('subject_id', 'subject_type'), False),
        )

class UserCallouts(BaseModel):
    dismissed_at = DateTimeField(null=True)
    feature_name = IntegerField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'user_callouts'
        indexes = (
            (('user', 'feature_name'), True),
        )

class UserCanonicalEmails(BaseModel):
    canonical_email = CharField(index=True)
    created_at = DateTimeField()
    id = BigAutoField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, unique=True)

    class Meta:
        table_name = 'user_canonical_emails'
        indexes = (
            (('user', 'canonical_email'), True),
        )

class UserCustomAttributes(BaseModel):
    created_at = DateTimeField()
    key = CharField()
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)
    value = CharField()

    class Meta:
        table_name = 'user_custom_attributes'
        indexes = (
            (('key', 'value'), False),
            (('user', 'key'), True),
        )

class UserDetails(BaseModel):
    bio = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    bio_html = TextField(null=True)
    cached_markdown_version = IntegerField(null=True)
    job_title = CharField(constraints=[SQL("DEFAULT ''::character varying")])
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, primary_key=True)
    webauthn_xid = TextField(null=True)

    class Meta:
        table_name = 'user_details'

class UserHighestRoles(BaseModel):
    highest_access_level = IntegerField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, primary_key=True)

    class Meta:
        table_name = 'user_highest_roles'
        indexes = (
            (('user', 'highest_access_level'), False),
        )

class UserInteractedProjects(BaseModel):
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'user_interacted_projects'
        indexes = (
            (('project', 'user'), True),
        )
        primary_key = CompositeKey('project', 'user')

class UserPreferences(BaseModel):
    created_at = DateTimeField()
    epic_notes_filter = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    epics_sort = CharField(null=True)
    experience_level = SmallIntegerField(null=True)
    feature_filter_type = BigIntegerField(null=True)
    first_day_of_week = IntegerField(null=True)
    gitpod_enabled = BooleanField(constraints=[SQL("DEFAULT false")], index=True)
    issue_notes_filter = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    issues_sort = CharField(null=True)
    merge_request_notes_filter = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    merge_requests_sort = CharField(null=True)
    projects_sort = CharField(null=True)
    render_whitespace_in_code = BooleanField(null=True)
    roadmap_epics_state = IntegerField(null=True)
    roadmaps_sort = CharField(null=True)
    setup_for_company = BooleanField(null=True)
    show_whitespace_in_diffs = BooleanField(constraints=[SQL("DEFAULT true")])
    sourcegraph_enabled = BooleanField(null=True)
    tab_width = SmallIntegerField(null=True)
    time_display_relative = BooleanField(null=True)
    time_format_in_24h = BooleanField(null=True)
    timezone = CharField(null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, unique=True)
    view_diffs_file_by_file = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'user_preferences'

class UserStatuses(BaseModel):
    availability = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    cached_markdown_version = IntegerField(null=True)
    emoji = CharField(constraints=[SQL("DEFAULT 'speech_balloon'::character varying")])
    message = CharField(null=True)
    message_html = CharField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, primary_key=True)

    class Meta:
        table_name = 'user_statuses'

class UserSyncedAttributesMetadata(BaseModel):
    email_synced = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    location_synced = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    name_synced = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    provider = CharField(null=True)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users, unique=True)

    class Meta:
        table_name = 'user_synced_attributes_metadata'

class UsersOpsDashboardProjects(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'users_ops_dashboard_projects'
        indexes = (
            (('user', 'project'), True),
        )

class UsersSecurityDashboardProjects(BaseModel):
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'users_security_dashboard_projects'
        indexes = (
            (('project', 'user'), True),
        )
        primary_key = CompositeKey('project', 'user')

class UsersStarProjects(BaseModel):
    created_at = DateTimeField(null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField(null=True)
    user_id = IntegerField()

    class Meta:
        table_name = 'users_star_projects'
        indexes = (
            (('user_id', 'project'), True),
        )

class UsersStatistics(BaseModel):
    blocked = IntegerField(constraints=[SQL("DEFAULT 0")])
    bots = IntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField()
    id = BigAutoField()
    updated_at = DateTimeField()
    with_highest_role_developer = IntegerField(constraints=[SQL("DEFAULT 0")])
    with_highest_role_guest = IntegerField(constraints=[SQL("DEFAULT 0")])
    with_highest_role_maintainer = IntegerField(constraints=[SQL("DEFAULT 0")])
    with_highest_role_owner = IntegerField(constraints=[SQL("DEFAULT 0")])
    with_highest_role_reporter = IntegerField(constraints=[SQL("DEFAULT 0")])
    without_groups_and_projects = IntegerField(constraints=[SQL("DEFAULT 0")])

    class Meta:
        table_name = 'users_statistics'

class Vulnerabilities(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    cached_markdown_version = IntegerField(null=True)
    confidence = SmallIntegerField()
    confidence_overridden = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    confirmed_at = DateTimeField(null=True)
    confirmed_by = ForeignKeyField(backref='users_confirmed_by_set', column_name='confirmed_by_id', field='id', model=Users, null=True)
    created_at = DateTimeField()
    description = TextField(null=True)
    description_html = TextField(null=True)
    dismissed_at = DateTimeField(null=True)
    dismissed_by = ForeignKeyField(backref='users_dismissed_by_set', column_name='dismissed_by_id', field='id', model=Users, null=True)
    due_date = DateField(null=True)
    due_date_sourcing_milestone = ForeignKeyField(column_name='due_date_sourcing_milestone_id', field='id', model=Milestones, null=True)
    epic = ForeignKeyField(column_name='epic_id', field='id', model=Epics, null=True)
    id = BigAutoField()
    last_edited_at = DateTimeField(null=True)
    last_edited_by = ForeignKeyField(backref='users_last_edited_by_set', column_name='last_edited_by_id', field='id', model=Users, null=True)
    milestone = ForeignKeyField(backref='milestones_milestone_set', column_name='milestone_id', field='id', model=Milestones, null=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    report_type = SmallIntegerField()
    resolved_at = DateTimeField(null=True)
    resolved_by = ForeignKeyField(backref='users_resolved_by_set', column_name='resolved_by_id', field='id', model=Users, null=True)
    resolved_on_default_branch = BooleanField(constraints=[SQL("DEFAULT false")])
    severity = SmallIntegerField()
    severity_overridden = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    start_date = DateField(null=True)
    start_date_sourcing_milestone = ForeignKeyField(backref='milestones_start_date_sourcing_milestone_set', column_name='start_date_sourcing_milestone_id', field='id', model=Milestones, null=True)
    state = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    title = CharField()
    title_html = TextField(null=True)
    updated_at = DateTimeField()
    updated_by = ForeignKeyField(backref='users_updated_by_set', column_name='updated_by_id', field='id', model=Users, null=True)

    class Meta:
        table_name = 'vulnerabilities'
        indexes = (
            (('id'), False),
            (('id'), False),
        )

class VulnerabilityExports(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    created_at = DateTimeField()
    file = CharField(null=True)
    file_store = IntegerField(index=True, null=True)
    finished_at = DateTimeField(null=True)
    format = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    group = ForeignKeyField(column_name='group_id', field='id', model=Namespaces, null=True)
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    started_at = DateTimeField(null=True)
    status = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_exports'

class VulnerabilityFeedback(BaseModel):
    author = ForeignKeyField(column_name='author_id', field='id', model=Users)
    category = SmallIntegerField()
    comment = TextField(null=True)
    comment_author = ForeignKeyField(backref='users_comment_author_set', column_name='comment_author_id', field='id', model=Users, null=True)
    comment_timestamp = DateTimeField(null=True)
    created_at = DateTimeField()
    feedback_type = SmallIntegerField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues, null=True)
    merge_request = ForeignKeyField(column_name='merge_request_id', field='id', model=MergeRequests, null=True)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines, null=True)
    project_fingerprint = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_feedback'
        indexes = (
            (('project', 'category', 'feedback_type', 'project_fingerprint'), True),
        )

class VulnerabilityIdentifiers(BaseModel):
    created_at = DateTimeField()
    external_id = CharField()
    external_type = CharField()
    fingerprint = BlobField()
    id = BigAutoField()
    name = CharField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    url = TextField(null=True)

    class Meta:
        table_name = 'vulnerability_identifiers'
        indexes = (
            (('project', 'fingerprint'), True),
        )

class VulnerabilityOccurrences(BaseModel):
    confidence = SmallIntegerField()
    created_at = DateTimeField()
    id = BigAutoField()
    location_fingerprint = BlobField()
    metadata_version = CharField()
    name = CharField()
    primary_identifier = ForeignKeyField(column_name='primary_identifier_id', field='id', model=VulnerabilityIdentifiers)
    project_fingerprint = BlobField(index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    raw_metadata = TextField()
    report_type = SmallIntegerField()
    scanner = ForeignKeyField(column_name='scanner_id', field='id', model=VulnerabilityScanners)
    severity = SmallIntegerField()
    updated_at = DateTimeField()
    uuid = CharField(unique=True)
    vulnerability = ForeignKeyField(column_name='vulnerability_id', field='id', model=Vulnerabilities, null=True)

    class Meta:
        table_name = 'vulnerability_occurrences'
        indexes = (
            (('project', 'primary_identifier', 'location_fingerprint', 'scanner'), True),
            (('project', 'report_type'), False),
        )

class VulnerabilityFindingLinks(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    name = TextField(null=True)
    updated_at = DateTimeField()
    url = TextField()
    vulnerability_occurrence = ForeignKeyField(column_name='vulnerability_occurrence_id', field='id', model=VulnerabilityOccurrences)

    class Meta:
        table_name = 'vulnerability_finding_links'

class VulnerabilityHistoricalStatistics(BaseModel):
    created_at = DateTimeField()
    critical = IntegerField(constraints=[SQL("DEFAULT 0")])
    date = DateField()
    high = IntegerField(constraints=[SQL("DEFAULT 0")])
    id = BigAutoField()
    info = IntegerField(constraints=[SQL("DEFAULT 0")])
    letter_grade = SmallIntegerField()
    low = IntegerField(constraints=[SQL("DEFAULT 0")])
    medium = IntegerField(constraints=[SQL("DEFAULT 0")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    total = IntegerField(constraints=[SQL("DEFAULT 0")])
    unknown = IntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_historical_statistics'
        indexes = (
            (('date', 'id'), False),
            (('project', 'date'), True),
        )

class VulnerabilityIssueLinks(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    link_type = SmallIntegerField(constraints=[SQL("DEFAULT 1")])
    updated_at = DateTimeField()
    vulnerability = ForeignKeyField(column_name='vulnerability_id', field='id', model=Vulnerabilities)

    class Meta:
        table_name = 'vulnerability_issue_links'
        indexes = (
            (('vulnerability', 'issue'), True),
            (('vulnerability', 'link_type'), True),
        )

class VulnerabilityOccurrenceIdentifiers(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    identifier = ForeignKeyField(column_name='identifier_id', field='id', model=VulnerabilityIdentifiers)
    occurrence = ForeignKeyField(column_name='occurrence_id', field='id', model=VulnerabilityOccurrences)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_occurrence_identifiers'
        indexes = (
            (('occurrence', 'identifier'), True),
        )

class VulnerabilityOccurrencePipelines(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    occurrence = ForeignKeyField(column_name='occurrence_id', field='id', model=VulnerabilityOccurrences)
    pipeline = ForeignKeyField(column_name='pipeline_id', field='id', model=CiPipelines)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_occurrence_pipelines'
        indexes = (
            (('occurrence', 'pipeline'), True),
        )

class VulnerabilityStatistics(BaseModel):
    created_at = DateTimeField()
    critical = IntegerField(constraints=[SQL("DEFAULT 0")])
    high = IntegerField(constraints=[SQL("DEFAULT 0")])
    id = BigAutoField()
    info = IntegerField(constraints=[SQL("DEFAULT 0")])
    letter_grade = SmallIntegerField(index=True)
    low = IntegerField(constraints=[SQL("DEFAULT 0")])
    medium = IntegerField(constraints=[SQL("DEFAULT 0")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, unique=True)
    total = IntegerField(constraints=[SQL("DEFAULT 0")])
    unknown = IntegerField(constraints=[SQL("DEFAULT 0")])
    updated_at = DateTimeField()

    class Meta:
        table_name = 'vulnerability_statistics'

class VulnerabilityUserMentions(BaseModel):
    id = BigAutoField()
    mentioned_groups_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_projects_ids = ArrayField(field_class=IntegerField, null=True)
    mentioned_users_ids = ArrayField(field_class=IntegerField, null=True)
    note = ForeignKeyField(column_name='note_id', field='id', model=Notes, null=True, unique=True)
    vulnerability = ForeignKeyField(column_name='vulnerability_id', field='id', model=Vulnerabilities, unique=True)

    class Meta:
        table_name = 'vulnerability_user_mentions'
        indexes = (
            (('vulnerability', 'note'), True),
        )

class WebHooks(BaseModel):
    confidential_issues_events = BooleanField(constraints=[SQL("DEFAULT false")])
    confidential_note_events = BooleanField(null=True)
    created_at = DateTimeField(null=True)
    deployment_events = BooleanField(constraints=[SQL("DEFAULT false")])
    enable_ssl_verification = BooleanField(constraints=[SQL("DEFAULT true")], null=True)
    encrypted_token = CharField(null=True)
    encrypted_token_iv = CharField(null=True)
    encrypted_url = CharField(null=True)
    encrypted_url_iv = CharField(null=True)
    feature_flag_events = BooleanField(constraints=[SQL("DEFAULT false")])
    group_id = IntegerField(index=True, null=True)
    issues_events = BooleanField(constraints=[SQL("DEFAULT false")])
    job_events = BooleanField(constraints=[SQL("DEFAULT false")])
    merge_requests_events = BooleanField(constraints=[SQL("DEFAULT false")])
    note_events = BooleanField(constraints=[SQL("DEFAULT false")])
    pipeline_events = BooleanField(constraints=[SQL("DEFAULT false")])
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects, null=True)
    push_events = BooleanField(constraints=[SQL("DEFAULT true")])
    push_events_branch_filter = TextField(null=True)
    releases_events = BooleanField(constraints=[SQL("DEFAULT false")])
    repository_update_events = BooleanField(constraints=[SQL("DEFAULT false")])
    service_id = IntegerField(null=True)
    tag_push_events = BooleanField(constraints=[SQL("DEFAULT false")], null=True)
    type = CharField(constraints=[SQL("DEFAULT 'ProjectHook'::character varying")], index=True, null=True)
    updated_at = DateTimeField(null=True)
    wiki_page_events = BooleanField(constraints=[SQL("DEFAULT false")])

    class Meta:
        table_name = 'web_hooks'

class WebHookLogs(BaseModel):
    created_at = DateTimeField()
    execution_duration = DoubleField(null=True)
    internal_error_message = CharField(null=True)
    request_data = TextField(null=True)
    request_headers = TextField(null=True)
    response_body = TextField(null=True)
    response_headers = TextField(null=True)
    response_status = CharField(null=True)
    trigger = CharField(null=True)
    updated_at = DateTimeField()
    url = CharField(null=True)
    web_hook = ForeignKeyField(column_name='web_hook_id', field='id', model=WebHooks)

    class Meta:
        table_name = 'web_hook_logs'
        indexes = (
            (('created_at', 'web_hook'), False),
        )

class WebauthnRegistrations(BaseModel):
    counter = BigIntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField()
    credential_xid = TextField(unique=True)
    id = BigAutoField()
    name = TextField()
    public_key = TextField()
    u2f_registration = ForeignKeyField(column_name='u2f_registration_id', field='id', model=U2FRegistrations, null=True)
    updated_at = DateTimeField()
    user = ForeignKeyField(column_name='user_id', field='id', model=Users)

    class Meta:
        table_name = 'webauthn_registrations'

class WikiPageMeta(BaseModel):
    created_at = DateTimeField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    title = CharField()
    updated_at = DateTimeField()

    class Meta:
        table_name = 'wiki_page_meta'

class WikiPageSlugs(BaseModel):
    canonical = BooleanField(constraints=[SQL("DEFAULT false")])
    created_at = DateTimeField()
    slug = CharField()
    updated_at = DateTimeField()
    wiki_page_meta = ForeignKeyField(column_name='wiki_page_meta_id', field='id', model=WikiPageMeta)

    class Meta:
        table_name = 'wiki_page_slugs'
        indexes = (
            (('slug', 'wiki_page_meta'), True),
        )

class X509Issuers(BaseModel):
    created_at = DateTimeField()
    crl_url = CharField()
    id = BigAutoField()
    subject = CharField()
    subject_key_identifier = CharField(index=True)
    updated_at = DateTimeField()

    class Meta:
        table_name = 'x509_issuers'

class X509Certificates(BaseModel):
    certificate_status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    created_at = DateTimeField()
    email = CharField()
    id = BigAutoField()
    serial_number = BlobField()
    subject = CharField()
    subject_key_identifier = CharField(index=True)
    updated_at = DateTimeField()
    x509_issuer = ForeignKeyField(column_name='x509_issuer_id', field='id', model=X509Issuers)

    class Meta:
        table_name = 'x509_certificates'

class X509CommitSignatures(BaseModel):
    commit_sha = BlobField(index=True)
    created_at = DateTimeField()
    id = BigAutoField()
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    verification_status = SmallIntegerField(constraints=[SQL("DEFAULT 0")])
    x509_certificate = ForeignKeyField(column_name='x509_certificate_id', field='id', model=X509Certificates)

    class Meta:
        table_name = 'x509_commit_signatures'

class ZoomMeetings(BaseModel):
    created_at = DateTimeField()
    id = BigAutoField()
    issue = ForeignKeyField(column_name='issue_id', field='id', model=Issues)
    issue_status = SmallIntegerField(constraints=[SQL("DEFAULT 1")], index=True)
    project = ForeignKeyField(column_name='project_id', field='id', model=Projects)
    updated_at = DateTimeField()
    url = CharField(null=True)

    class Meta:
        table_name = 'zoom_meetings'
        indexes = (
            (('issue', 'issue_status'), True),
        )

