require 'rails_helper'

include SessionTimeoutWarningHelper
include ActionView::Helpers::DateHelper

feature 'Sign in' do
  scenario 'user cannot sign in if not registered' do
    signin('test@example.com', 'Please123!')
    expect(page).to have_content t('devise.failure.not_found_in_database')
  end

  scenario 'user cannot sign in with wrong email' do
    user = create(:user)
    signin('invalid@email.com', user.password)
    expect(page).to have_content t('devise.failure.not_found_in_database')
  end

  scenario 'user cannot sign in with empty email' do
    signin('', 'foo')

    expect(page).to have_content t('devise.failure.invalid')
  end

  scenario 'user cannot sign in with empty password' do
    signin('test@example.com', '')

    expect(page).to have_content t('devise.failure.invalid')
  end

  scenario 'user cannot sign in with wrong password' do
    user = create(:user)
    signin(user.email, 'invalidpass')
    expect(page).to have_content t('devise.failure.invalid')
  end

  scenario 'user can see and use password visibility toggle', js: true do
    visit new_user_session_path

    find('#pw-toggle-0', visible: false).trigger('click')

    expect(page).to have_css('input.password[type="text"]')
  end

  scenario 'user session expires in amount of time specified by Devise config' do
    sign_in_and_2fa_user

    visit profile_path
    expect(current_path).to eq profile_path

    Timecop.travel(Devise.timeout_in + 1.minute)

    visit profile_path
    expect(current_path).to eq root_path

    Timecop.return
  end

  context 'session approaches timeout', js: true do
    before :each do
      allow(Figaro.env).to receive(:session_check_frequency).and_return('1')
      allow(Figaro.env).to receive(:session_check_delay).and_return('2')
      allow(Figaro.env).to receive(:session_timeout_warning_seconds).
        and_return(Devise.timeout_in.to_s)

      sign_in_and_2fa_user
      visit root_path
    end

    scenario 'user sees warning before session times out' do
      expect(page).to have_css('#session-timeout-msg')

      request_headers = page.driver.network_traffic.flat_map(&:headers).uniq
      ajax_headers = { 'name' => 'X-Requested-With', 'value' => 'XMLHttpRequest' }

      expect(request_headers).to include ajax_headers
      expect(page).to have_content('7:59')
      expect(page).to have_content('7:58')
    end

    scenario 'user can continue browsing' do
      find_link(t('notices.timeout_warning.signed_in.continue')).trigger('click')

      expect(current_path).to eq profile_path
    end

    scenario 'user has option to sign out' do
      click_link(t('notices.timeout_warning.signed_in.sign_out'))

      expect(page).to have_content t('devise.sessions.signed_out')
      expect(current_path).to eq new_user_session_path
    end
  end

  context 'user only signs in via email and password', js: true do
    it 'displays the session timeout warning with partially signed in copy' do
      allow(Figaro.env).to receive(:session_check_frequency).and_return('1')
      allow(Figaro.env).to receive(:session_check_delay).and_return('2')
      allow(Figaro.env).to receive(:session_timeout_warning_seconds).
        and_return(Devise.timeout_in.to_s)

      user = create(:user, :signed_up)
      sign_in_user(user)
      visit user_two_factor_authentication_path

      expect(page).to have_css('#session-timeout-msg')
      expect(page).to have_content(t('notices.timeout_warning.partially_signed_in.continue'))
      expect(page).to have_content(t('notices.timeout_warning.partially_signed_in.sign_out'))
    end
  end

  context 'signed out' do
    it 'refreshes the current page after session expires', js: true do
      allow(Devise).to receive(:timeout_in).and_return(1)

      visit sign_up_email_path
      fill_in 'Email', with: 'test@example.com'

      expect(page).to have_content(t('session_cleared'))

      expect(page).to have_field('Email', with: '')
      expect(page).to have_current_path(sign_up_email_path(timeout: true))
    end

    it 'does not refresh the page after the session expires', js: true do
      allow(Devise).to receive(:timeout_in).and_return(60)

      visit root_path
      expect(page).to_not have_content(t('session_cleared'))
    end
  end

  context 'signing back in after session timeout length' do
    before do
      ActionController::Base.allow_forgery_protection = true
    end

    after do
      ActionController::Base.allow_forgery_protection = false
    end

    it 'fails to sign in the user, with CSRF error' do
      user = sign_in_and_2fa_user
      click_link(t('links.sign_out'))

      Timecop.travel(Devise.timeout_in + 1.minute) do
        expect(page).to_not have_content(t('forms.buttons.continue'))

        fill_in_credentials_and_submit(user.email, user.password)
        expect(page).to have_content t('errors.invalid_authenticity_token')

        fill_in_credentials_and_submit(user.email, user.password)
        expect(current_path).to eq user_two_factor_authentication_path
      end
    end

    it 'refreshes the page (which clears the form) and notifies the user', js: true do
      allow(Devise).to receive(:timeout_in).and_return(1)
      user = create(:user)
      visit root_path
      fill_in 'Email', with: user.email
      fill_in 'Password', with: user.password

      expect(page).to have_content(t('session_cleared'))
      expect(find_field('Email').value).to be_blank
      expect(find_field('Password').value).to be_blank
    end
  end

  describe 'session timeout configuration' do
    it 'uses delay and warning settings whose sum is a multiple of 60' do
      expect((start + warning) % 60).to eq 0
    end

    it 'uses frequency and warning settings whose sum is a multiple of 60' do
      expect((frequency + warning) % 60).to eq 0
    end
  end

  context 'user attempts too many concurrent sessions' do
    scenario 'redirects to home page with error' do
      user = user_with_2fa

      perform_in_browser(:one) do
        sign_in_live_with_2fa(user)

        expect(current_path).to eq profile_path
      end

      perform_in_browser(:two) do
        sign_in_live_with_2fa(user)

        expect(current_path).to eq profile_path
      end

      perform_in_browser(:one) do
        visit profile_path

        expect(current_path).to eq new_user_session_path
        expect(page).to have_content(t('devise.failure.session_limited'))
      end
    end
  end
end
