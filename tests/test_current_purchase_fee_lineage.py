import pytest
from solslot_api.generation_customer_purchase_fee_lineage import FeeExposure,calculate_fee_lineage


def h(n):return '0x'+format(n,'064x')


def test_prior_and_uncertain_work_counts_across_policy_transition_without_reset():
    old=FeeExposure(h(1),100,'CONFIRMED')
    uncertain=FeeExposure(h(2),200,'UNKNOWN')
    pending=FeeExposure(h(3),300,'PREPARED')
    balance=calculate_fee_lineage(1000,[old,uncertain,pending,FeeExposure(h(1),100,'FUNDED')])
    assert (balance.committed_mojos,balance.remaining_mojos,balance.distinct_exposures)==(600,400,3)
    with pytest.raises(ValueError,match='LIMIT_EXCEEDED'):
        calculate_fee_lineage(1000,[old,uncertain,pending,FeeExposure(h(4),401,'SIGNED')])


def test_conflicting_or_unverified_exposure_never_creates_allowance():
    with pytest.raises(ValueError,match='CONFLICTING_EXPOSURE'):
        calculate_fee_lineage(1000,[FeeExposure(h(1),100,'CONFIRMED'),FeeExposure(h(1),0,'PENDING')])
    for exposure in (FeeExposure(h(1),-1,'CONFIRMED'),FeeExposure(h(1),True,'PREPARED'),
                     FeeExposure(h(1),5,'RELEASED'),FeeExposure('invalid',5,'FUNDED')):
        with pytest.raises(ValueError,match='EXPOSURE_INVALID'):calculate_fee_lineage(1000,[exposure])
    for limit in (0,True,-1):
        with pytest.raises(ValueError,match='FINITE_LIMIT_REQUIRED'):calculate_fee_lineage(limit,[])
