"""Default-closed construction of the separately authorized pricing worker."""
from .generation_customer_runtime import GenerationCustomerRuntime
from .generation_customer_identity_runtime import CurrentCustomerIdentityRuntime
from .generation_customer_purchase_store import CurrentCustomerPurchaseStore
from .generation_price_demand import PriceDemandRuntime
from .generation_price_demand_socket import PriceDemandSocketCollector


def configured_price_demand(settings,*,customers,identity):
    if not getattr(settings,'generation_customer_pricing_enabled',False):
        return None
    generation=settings.deployment_generation_id
    if (settings.network!='testnet11' or not generation
            or not isinstance(customers,GenerationCustomerRuntime)
            or customers.store.generation_id!=generation
            or not isinstance(identity,CurrentCustomerIdentityRuntime)
            or identity.customers is not customers
            or settings.generation_customer_pricing_socket!='/run/solslot-price-demand/input.sock'
            or type(settings.generation_customer_pricing_socket_gid)is not int
            or settings.generation_customer_pricing_socket_gid<0):
        raise ValueError('CURRENT_PRICE_RUNTIME_CONFIGURATION_INVALID')
    store=CurrentCustomerPurchaseStore(settings.payment_purchase_db_path,generation)
    collector=PriceDemandSocketCollector(settings.generation_customer_pricing_socket,
        expected_uid=0,expected_gid=settings.generation_customer_pricing_socket_gid)
    return PriceDemandRuntime(store=store,health=collector.status,collect=collector,enabled=True)
