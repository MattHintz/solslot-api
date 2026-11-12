from copy import deepcopy
import pytest
from pydantic import ValidationError
from solslot_api.property_metadata import PropertyDossierDraftV1,PropertyDossierV1
from tests.test_collection_store import dossier_payload,verified_store

def test_separate_roles_persist_and_are_committed():
    payload=dossier_payload()
    payload['projectTeam']={
        'sponsor':{'legalName':'Project Sponsor LLC','displayName':'Project Sponsor','website':'https://sponsor.example/'},
        'builderStatus':'selected','builderIsSponsor':False,
        'builder':{'legalName':'Independent Builder LLC','licenseReference':'supplied for review'},
    }
    store,collection=verified_store()
    saved=store.update_draft('HARBOR-17',draft=PropertyDossierDraftV1.model_validate(payload),expected_revision=collection['revision'],actor_subject='0xowner')
    assert store.get('HARBOR-17')['dossier']['projectTeam']==payload['projectTeam']
    full=PropertyDossierV1.model_validate(payload)
    changed=deepcopy(payload);changed['projectTeam']['builder']['legalName']='Other Builder LLC'
    assert full.commitment().metadata_root!=PropertyDossierV1.model_validate(changed).commitment().metadata_root

def test_shared_party_has_one_profile_and_two_roles():
    payload=dossier_payload();payload['projectTeam']={'sponsor':{'legalName':'Sponsor and Builder LLC'},'builderStatus':'selected','builderIsSponsor':True}
    sealed=PropertyDossierDraftV1.model_validate(payload).to_sealed_dossier().canonical_payload()
    assert sealed['projectTeam']['builderIsSponsor'] is True and 'builder' not in sealed['projectTeam']
    payload['projectTeam']['builder']={'legalName':'Conflicting Builder LLC'}
    with pytest.raises(ValidationError):PropertyDossierV1.model_validate(payload)

@pytest.mark.parametrize('status',['not-appointed','not-applicable'])
def test_unappointed_builder_is_explicit(status):
    payload=dossier_payload();payload['projectTeam']['builderStatus']=status
    assert PropertyDossierV1.model_validate(payload).project_team.builder is None

def test_incomplete_draft_saves_but_review_requires_names_and_status():
    draft=PropertyDossierDraftV1(collectionId='new',title='New property',revision=1,projectTeam={'sponsor':{},'builderIsSponsor':False})
    assert draft.project_team.sponsor.legal_name is None
    with pytest.raises(ValidationError):draft.to_sealed_dossier()
    store,collection=verified_store();payload=dossier_payload();payload.pop('projectTeam')
    old=PropertyDossierV1.model_validate(payload)
    assert 'projectTeam' not in old.canonical_payload()  # Historic metadata roots unchanged.
    store.update_draft('HARBOR-17',draft=PropertyDossierDraftV1.model_validate(payload),expected_revision=collection['revision'],actor_subject='0xowner')
    assert any(x['path']=='/projectTeam' for x in store.readiness('HARBOR-17')['issues'])

@pytest.mark.parametrize('url',['javascript:alert(1)','http://example.com','https://user:secret@example.com','https:///missing'])
def test_unsafe_profile_links_are_rejected(url):
    payload=dossier_payload();payload['projectTeam']['sponsor']['website']=url
    with pytest.raises(ValidationError):PropertyDossierDraftV1.model_validate(payload)
