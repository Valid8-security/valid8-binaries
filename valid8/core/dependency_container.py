"""
Dependency Injection Container - Manages service dependencies
"""
from typing import Dict, Any, Type, TypeVar, Generic, Optional
from abc import ABC, abstractmethod

T = TypeVar('T')


class IServiceProvider(ABC):
    """Interface for service providers"""

    @abstractmethod
    def get_service(self, service_type: Type[T]) -> T:
        """Get service instance"""
        pass

    @abstractmethod
    def register_service(self, service_type: Type[T], implementation: Type[T],
                        lifetime: str = "transient") -> None:
        """Register service with container"""
        pass

    @abstractmethod
    def register_instance(self, service_type: Type[T], instance: T) -> None:
        """Register service instance"""
        pass


class ServiceLifetime:
    """Service lifetime constants"""
    TRANSIENT = "transient"  # New instance each time
    SCOPED = "scoped"       # One instance per scope
    SINGLETON = "singleton" # One instance for entire application


class ServiceDescriptor:
    """Service registration descriptor"""

    def __init__(self, implementation: Type, lifetime: str = ServiceLifetime.TRANSIENT):
        self.implementation = implementation
        self.lifetime = lifetime
        self.instance = None


class DependencyContainer(IServiceProvider):
    """Simple dependency injection container"""

    def __init__(self):
        self._services: Dict[Type, ServiceDescriptor] = {}
        self._scoped_instances: Dict[Type, Any] = {}

    def register_service(self, service_type: Type[T], implementation: Type[T],
                        lifetime: str = ServiceLifetime.TRANSIENT) -> None:
        """Register service with container"""
        self._services[service_type] = ServiceDescriptor(implementation, lifetime)

    def register_instance(self, service_type: Type[T], instance: T) -> None:
        """Register service instance (singleton)"""
        descriptor = ServiceDescriptor(type(instance), ServiceLifetime.SINGLETON)
        descriptor.instance = instance
        self._services[service_type] = descriptor

    def get_service(self, service_type: Type[T]) -> T:
        """Get service instance"""
        if service_type not in self._services:
            raise ValueError(f"Service {service_type} not registered")

        descriptor = self._services[service_type]

        if descriptor.lifetime == ServiceLifetime.SINGLETON:
            if descriptor.instance is None:
                descriptor.instance = descriptor.implementation()
            return descriptor.instance

        elif descriptor.lifetime == ServiceLifetime.SCOPED:
            if service_type not in self._scoped_instances:
                self._scoped_instances[service_type] = descriptor.implementation()
            return self._scoped_instances[service_type]

        else:  # TRANSIENT
            return descriptor.implementation()

    def create_scope(self) -> 'ServiceScope':
        """Create a new service scope"""
        return ServiceScope(self)

    def clear_scoped_instances(self) -> None:
        """Clear all scoped instances"""
        self._scoped_instances.clear()


class ServiceScope:
    """Service scope for scoped lifetime services"""

    def __init__(self, container: DependencyContainer):
        self._container = container
        self._instances: Dict[Type, Any] = {}

    def get_service(self, service_type: Type[T]) -> T:
        """Get service instance within this scope"""
        if service_type not in self._container._services:
            raise ValueError(f"Service {service_type} not registered")

        descriptor = self._services[service_type]

        if descriptor.lifetime == ServiceLifetime.SINGLETON:
            return self._container.get_service(service_type)

        elif descriptor.lifetime == ServiceLifetime.SCOPED:
            if service_type not in self._instances:
                self._instances[service_type] = descriptor.implementation()
            return self._instances[service_type]

        else:  # TRANSIENT
            return descriptor.implementation()

    def dispose(self) -> None:
        """Dispose of scoped instances"""
        self._instances.clear()


# Global container instance
container = DependencyContainer()


def register_service(service_type: Type[T], implementation: Type[T],
                    lifetime: str = ServiceLifetime.TRANSIENT) -> None:
    """Convenience function to register service"""
    container.register_service(service_type, implementation, lifetime)


def get_service(service_type: Type[T]) -> T:
    """Convenience function to get service"""
    return container.get_service(service_type)

