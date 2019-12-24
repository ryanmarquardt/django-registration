"""
A two-step (registration followed by activation) workflow, implemented
by emailing an HMAC-verified timestamped activation token to the user
on signup.

"""

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import signing
from django.urls import reverse_lazy
from django.utils.translation import ugettext_lazy as _
from django.views.generic import FormView

from django_registration.backends.activation.views import (
    REGISTRATION_SALT, RegistrationView
)
from django_registration.exceptions import ActivationError
from django_registration.views import BaseActivationView


__all__ = ['RegistrationView', 'ActivationForm', 'ActivationView']


class ActivationForm(forms.Form):
    """
    Accept activation key via a POST request.

    """
    # Django accepts usernames of up to 150 unicode characters. The
    # minimum necessary length is determined by:
    # len(signing.dumps('\uABCD' * 150))
    activation_key = forms.CharField(max_length=1238)


class ActivationView(FormView, BaseActivationView):
    """
    Given a valid activation key, activate the user's
    account. Otherwise, show an error message stating the account
    couldn't be activated.

    """
    ALREADY_ACTIVATED_MESSAGE = _(
        u'The account you tried to activate has already been activated.'
    )
    BAD_USERNAME_MESSAGE = _(
        u'The account you attempted to activate is invalid.'
    )
    EXPIRED_MESSAGE = _(u'This account has expired.')
    INVALID_KEY_MESSAGE = _(
        u'The activation key you provided is invalid.'
    )

    template_name = 'django_registration/activation_form.html'
    form_class = ActivationForm
    success_url = reverse_lazy('django_registration_activation_complete')

    def get_context_data(self, *args, **kwargs):
        result = super(ActivationView, self).get_context_data(*args, **kwargs)
        result['activation_key'] = kwargs['activation_key']
        return result

    def form_valid(self, form):
        return self._attempt_activation(
            activation_key=form.cleaned_data['activation_key']
        )

    def activate(self, *args, **kwargs):
        username = self.validate_key(kwargs.get('activation_key'))
        user = self.get_user(username)
        user.is_active = True
        user.save()
        return user

    def validate_key(self, activation_key):
        """
        Verify that the activation key is valid and within the
        permitted activation time window, returning the username if
        valid or raising ``ActivationError`` if not.

        """
        try:
            username = signing.loads(
                activation_key,
                salt=REGISTRATION_SALT,
                max_age=settings.ACCOUNT_ACTIVATION_DAYS * 86400
            )
            return username
        except signing.SignatureExpired:
            raise ActivationError(
                self.EXPIRED_MESSAGE,
                code='expired'
            )
        except signing.BadSignature:
            raise ActivationError(
                self.INVALID_KEY_MESSAGE,
                code='invalid_key',
                params={'activation_key': activation_key}
            )

    def get_user(self, username):
        """
        Given the verified username, look up and return the
        corresponding user account if it exists, or raising
        ``ActivationError`` if it doesn't.

        """
        User = get_user_model()
        try:
            user = User.objects.get(**{
                User.USERNAME_FIELD: username,
            })
            if user.is_active:
                raise ActivationError(
                    self.ALREADY_ACTIVATED_MESSAGE,
                    code='already_activated'
                )
            return user
        except User.DoesNotExist:
            raise ActivationError(
                self.BAD_USERNAME_MESSAGE,
                code='bad_username'
            )
