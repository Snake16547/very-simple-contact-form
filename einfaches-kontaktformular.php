<?php
/**
 * Plugin Name: Einfaches Kontaktformular
 * Description: Gutenberg-Kontaktformular mit Honeypot, SMTP, Diagnose und fünf Sprachen.
 * Version: 1.2.1
 * Requires at least: 6.3
 * Requires PHP: 7.4
 * Author: Nils Hünerfürst
 * Author URI: https://huenerfuerst.de/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: einfaches-kontaktformular
 */
if (!defined('ABSPATH')) { exit; }
function nh_ekf_lang($front=false) {
    $v=$front ? get_option('ekf_language','auto') : 'auto';
    if ($v==='auto') { $v=substr(strtolower($front ? get_locale() : determine_locale()),0,2); }
    return in_array($v,array('de','en','es','zh','hi'),true) ? $v : 'en';
}
function nh_ekf_t($key,$l='') {
    static $text;
    if (!$text) { $text=json_decode(file_get_contents(__DIR__.'/languages.json'),true); }
    return $text[$l ?: nh_ekf_lang()][$key] ?? $text['en'][$key] ?? $key;
}
function nh_ekf_input($key) {
    // Callers verify the action nonce first and validate or sanitize each field.
    // phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    return isset($_POST[$key]) && is_string($_POST[$key]) ? wp_unslash($_POST[$key]) : '';
    // phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
}
function nh_ekf_host_ok($host) {
    return is_string($host) && strlen($host)<=253 && strpos($host,'.')!==false &&
        preg_match('/\A[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\z/iD',$host) && strpos($host,'..')===false;
}
function nh_ekf_smtp_ready($s) {
    return is_array($s) && !empty($s['host']) && nh_ekf_host_ok($s['host']) && !empty($s['user']) &&
        !empty($s['password']) && isset($s['security']) && in_array($s['security'],array('ssl','tls'),true) &&
        is_email(get_option('ekf_sender','')) && is_email(get_option('ekf_recipient',get_option('admin_email')));
}
function nh_ekf_log($status,$source) {
    update_option('ekf_last_status',array('status'=>$status,'source'=>$source,'time'=>time()),false);
}
function nh_ekf_mail($to,$subject,$body,$reply,$source) {
    $s=get_option('ekf_smtp',array());
    if (!nh_ekf_smtp_ready($s)) {
        nh_ekf_log('config',$source);
        return false;
    }

    // Use WordPress's bundled PHPMailer with a separate instance for this plugin.
    require_once ABSPATH . WPINC . '/PHPMailer/Exception.php';
    require_once ABSPATH . WPINC . '/PHPMailer/PHPMailer.php';
    require_once ABSPATH . WPINC . '/PHPMailer/SMTP.php';

    $sender=get_option('ekf_sender');
    $mailer=new \PHPMailer\PHPMailer\PHPMailer(true);
    $mailer->isSMTP();
    $mailer->Host=$s['host'];
    $mailer->Port=$s['security']==='ssl' ? 465 : 587;
    $mailer->SMTPAuth=true;
    $mailer->Username=$s['user'];
    $mailer->Password=$s['password'];
    $mailer->SMTPSecure=$s['security'];
    $mailer->SMTPOptions=array('ssl'=>array('verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false));
    $mailer->Timeout=15;
    $mailer->Timelimit=20;
    $mailer->CharSet='UTF-8';

    try {
        $mailer->setFrom($sender,wp_specialchars_decode(get_bloginfo('name'),ENT_QUOTES));
        $mailer->addAddress($to);
        if (is_email($reply)) {
            $mailer->addReplyTo($reply);
        }
        $mailer->Subject=$subject;
        $mailer->Body=$body;
        $sent=$mailer->send();
    } catch (\PHPMailer\PHPMailer\Exception $failure) {
        $sent=false;
    } finally {
        $mailer->smtpClose();
    }
    nh_ekf_log($sent ? 'accepted' : 'mailerror',$source);
    return $sent;
}
add_action('init',function () {
    register_block_type(__DIR__,array('render_callback'=>'nh_ekf_render'));
    wp_localize_script('ekf-kontaktformular-editor-script','ekfEditor',array('title'=>nh_ekf_t('title'),'preview'=>nh_ekf_t('preview')));
});
add_action('admin_menu',function () { add_options_page(nh_ekf_t('title'),nh_ekf_t('title'),'manage_options','ekf','nh_ekf_admin'); });
add_action('admin_post_ekf_save',function () {
    if (!current_user_can('manage_options')) { wp_die('403','',array('response'=>403)); }
    check_admin_referer('ekf_save');
    nh_ekf_require_post();
    $to=trim(nh_ekf_input('ekf_recipient')); $from=trim(nh_ekf_input('ekf_sender'));
    $host=trim(nh_ekf_input('ekf_host')); $user=trim(nh_ekf_input('ekf_user')); $security=nh_ekf_input('ekf_security');
    if (!is_email($to) || !is_email($from) || !nh_ekf_host_ok($host) || !$user || preg_match('/[\r\n]/',$to.$from.$user) || !in_array($security,array('ssl','tls'),true)) {
        wp_safe_redirect(admin_url('options-general.php?page=ekf&ekf_notice=invalidsettings'),303); exit;
    }
    $old=get_option('ekf_smtp',array()); $password=nh_ekf_input('ekf_password');
    if (nh_ekf_input('ekf_clearpass')==='1') { $password=''; }
    elseif ($password==='') { $password=$old['password'] ?? ''; }
    $l=nh_ekf_input('ekf_language');
    update_option('ekf_recipient',sanitize_email($to),false);
    update_option('ekf_sender',sanitize_email($from),false);
    update_option('ekf_language',in_array($l,array('auto','de','en','es','zh','hi'),true) ? $l : 'auto',false);
    update_option('ekf_smtp',array('host'=>$host,'user'=>$user,'security'=>$security,'password'=>$password),false);
    wp_safe_redirect(admin_url('options-general.php?page=ekf&ekf_notice=saved'),303); exit;
});
function nh_ekf_admin() {
    if (!current_user_can('manage_options')) { return; }
    $s=get_option('ekf_smtp',array());
    echo '<div class="wrap"><h1>'.esc_html(nh_ekf_t('title')).'</h1>';
    // This read-only flag only selects an allowlisted display message.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $notice=isset($_GET['ekf_notice']) && is_string($_GET['ekf_notice']) ? sanitize_key(wp_unslash($_GET['ekf_notice'])) : '';
    if (in_array($notice,array('saved','invalidsettings'),true)) { echo '<div class="notice notice-'.($notice==='saved' ? 'success' : 'error').'"><p>'.esc_html(nh_ekf_t($notice)).'</p></div>'; }
    echo '<p>'.esc_html(nh_ekf_t('settingshelp')).'</p><form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="ekf_save">';
    wp_nonce_field('ekf_save');
    $fields=array(
        'recipient'=>array('ekf_recipient',get_option('ekf_recipient',get_option('admin_email')),'email'),
        'sender'=>array('ekf_sender',get_option('ekf_sender',''),'email'),
        'host'=>array('ekf_host',$s['host'] ?? '','text'),
        'user'=>array('ekf_user',$s['user'] ?? '','text')
    );
    foreach ($fields as $label=>$f) {
        echo '<p><label for="'.esc_attr($f[0]).'">'.esc_html(nh_ekf_t($label)).'</label></p><input class="regular-text" id="'.esc_attr($f[0]).'" name="'.esc_attr($f[0]).'" type="'.esc_attr($f[2]).'" value="'.esc_attr($f[1]).'" required>';
    }
    echo '<p><label for="ekf_password">'.esc_html(nh_ekf_t('password')).'</label></p><input class="regular-text" id="ekf_password" name="ekf_password" type="password" value="" autocomplete="new-password"><p>'.esc_html(nh_ekf_t('passhelp')).'</p><p><label><input type="checkbox" name="ekf_clearpass" value="1"> '.esc_html(nh_ekf_t('clearpass')).'</label></p><p>'.esc_html(nh_ekf_t('clearhelp')).'</p>';
    echo '<p><label for="ekf_security">'.esc_html(nh_ekf_t('security')).'</label></p><select id="ekf_security" name="ekf_security">';
    foreach (array('ssl'=>'TLS (SMTPS) — 465','tls'=>'STARTTLS — 587') as $v=>$label) { echo '<option value="'.esc_attr($v).'" '.selected($s['security'] ?? 'ssl',$v,false).'>'.esc_html($label).'</option>'; }
    echo '</select><p>'.esc_html(nh_ekf_t('smtphelp')).'</p><p><label for="ekf_language">'.esc_html(nh_ekf_t('language')).'</label></p><select id="ekf_language" name="ekf_language">';
    foreach (array('auto'=>nh_ekf_t('auto'),'de'=>'Deutsch','en'=>'English','es'=>'Español','zh'=>'简体中文','hi'=>'हिन्दी') as $v=>$label) { echo '<option value="'.esc_attr($v).'" '.selected(get_option('ekf_language','auto'),$v,false).'>'.esc_html($label).'</option>'; }
    echo '</select>'; submit_button(nh_ekf_t('save')); echo '</form><hr><h2>'.esc_html(nh_ekf_t('diagnosis')).'</h2>';
    if (!nh_ekf_smtp_ready($s)) { echo '<p>'.esc_html(nh_ekf_t('config')).'</p>'; }
    $last=get_option('ekf_last_status');
    if (is_array($last) && isset($last['status'],$last['time'],$last['source'])) {
        echo '<p>'.esc_html(nh_ekf_t($last['status'])).'</p><p>'.esc_html(nh_ekf_t('time').': '.wp_date('Y-m-d H:i:s',$last['time'])).'</p><p>'.esc_html(nh_ekf_t('source').': '.nh_ekf_t($last['source'])).'</p>';
    } else { echo '<p>'.esc_html(nh_ekf_t('none')).'</p>'; }
    echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="ekf_test">'; wp_nonce_field('ekf_test'); submit_button(nh_ekf_t('test'),'secondary'); echo '</form></div>';
}
add_action('admin_post_ekf_test',function () {
    if (!current_user_can('manage_options')) { wp_die('403','',array('response'=>403)); }
    check_admin_referer('ekf_test');
    nh_ekf_require_post();
    $key='ekf_test_'.get_current_user_id();
    if (!get_transient($key)) { set_transient($key,1,10); nh_ekf_mail(get_option('ekf_recipient',get_option('admin_email')),nh_ekf_t('testsubject'),nh_ekf_t('testbody'),'','testsource'); }
    wp_safe_redirect(admin_url('options-general.php?page=ekf'),303); exit;
});
function nh_ekf_render() {
    $page=get_queried_object_id(); if (!$page || !is_singular()) { return ''; }
    $l=nh_ekf_lang(true); $id=wp_unique_id('ekf-');
    // This read-only flag only selects an allowlisted display message.
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $status=isset($_GET['ekf_status']) && is_string($_GET['ekf_status']) ? sanitize_key(wp_unslash($_GET['ekf_status'])) : '';
    ob_start(); ?>
    <?php
    // Core escapes each attribute value before assembling the wrapper attributes.
    ?><div <?php echo get_block_wrapper_attributes(array('class'=>'ekf-contact')); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    ?> id="kontaktformular" lang="<?php echo esc_attr($l==='zh' ? 'zh-Hans' : $l); ?>">
    <?php if (in_array($status,array('ok','invalid','numbers','expired','limit','failed'),true)) : ?><p class="ekf-notice" role="status"><?php echo esc_html(nh_ekf_t($status,$l)); ?></p><?php endif; ?>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
    <input type="hidden" name="action" value="ekf_send"><input type="hidden" name="ekf_page" value="<?php echo esc_attr($page); ?>">
    <?php wp_nonce_field('ekf_send_'.$page,'ekf_nonce',false); ?>
    <div class="ekf-trap" aria-hidden="true"><label for="<?php echo esc_attr($id); ?>website"><?php echo esc_html(nh_ekf_t('trap',$l)); ?></label><input id="<?php echo esc_attr($id); ?>website" name="ekf_website" type="text" value="" tabindex="-1" autocomplete="off"></div>
    <?php foreach (array('name'=>array('text','name',100),'email'=>array('email','email',254)) as $field=>$spec) : ?>
    <p><label for="<?php echo esc_attr($id.$field); ?>"><?php echo esc_html(nh_ekf_t($field,$l).' ('.nh_ekf_t('required',$l).')'); ?></label><input id="<?php echo esc_attr($id.$field); ?>" name="<?php echo esc_attr('ekf_'.$field); ?>" type="<?php echo esc_attr($spec[0]); ?>" autocomplete="<?php echo esc_attr($spec[1]); ?>" maxlength="<?php echo esc_attr($spec[2]); ?>" required></p>
    <?php endforeach; ?>
    <p><label for="<?php echo esc_attr($id); ?>message"><?php echo esc_html(nh_ekf_t('message',$l).' ('.nh_ekf_t('required',$l).')'); ?></label><textarea id="<?php echo esc_attr($id); ?>message" name="ekf_message" rows="7" maxlength="5000" required></textarea></p>
    <p class="ekf-privacy"><?php echo esc_html(nh_ekf_t('privacy',$l)); ?> <?php if (get_privacy_policy_url()) : ?><a href="<?php echo esc_url(get_privacy_policy_url()); ?>"><?php echo esc_html(nh_ekf_t('policy',$l)); ?></a><?php endif; ?></p>
    <button type="submit"><?php echo esc_html(nh_ekf_t('send',$l)); ?></button></form></div>
    <?php return ob_get_clean();
}
function nh_ekf_finish($page,$status) { wp_safe_redirect(add_query_arg('ekf_status',$status,get_permalink($page) ?: home_url('/')).'#kontaktformular',303); exit; }
add_action('admin_post_nopriv_ekf_send','nh_ekf_send'); add_action('admin_post_ekf_send','nh_ekf_send');
function nh_ekf_require_post() {
    $method=isset($_SERVER['REQUEST_METHOD']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])) : '';
    if ($method!=='POST') { wp_die('405','',array('response'=>405)); }
}
function nh_ekf_send() {
    nocache_headers();
    nh_ekf_require_post();
    $page=absint(nh_ekf_input('ekf_page')); $post=get_post($page);
    if (!$post || $post->post_status!=='publish' || !is_post_publicly_viewable($post)) { wp_die('404','',array('response'=>404)); }
    if (!wp_verify_nonce(nh_ekf_input('ekf_nonce'),'ekf_send_'.$page)) { nh_ekf_finish($page,'expired'); }
    if (trim(nh_ekf_input('ekf_website'))!=='') { nh_ekf_log('blocked','formsource'); nh_ekf_finish($page,'ok'); }
    $rn=nh_ekf_input('ekf_name'); $re=trim(nh_ekf_input('ekf_email')); $rm=nh_ekf_input('ekf_message');
    $name=sanitize_text_field($rn); $email=sanitize_email($re); $message=sanitize_textarea_field($rm);
    $len=function ($v) { return function_exists('mb_strlen') ? mb_strlen($v,'UTF-8') : strlen($v); };
    if ($name==='' || $message==='' || !is_email($re) || $email!==$re || preg_match('/[\r\n]/',$re) || $len($rn)>100 || strlen($re)>254 || $len($rm)>5000) { nh_ekf_finish($page,'invalid'); }
    // Reject digit-only messages, including Unicode digits and number separators.
    if (preg_match('/\A(?=[^\p{Nd}]*\p{Nd})[\p{Nd}\p{Z}\p{Cf}\p{Pd}\s.,()+\/]+\z/u',$message)) {
        nh_ekf_finish($page,'numbers');
    }
    $ip=isset($_SERVER['REMOTE_ADDR']) && is_string($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
    $key='ekf_'.hash_hmac('sha256',$ip,wp_salt('auth')); $state=get_transient($key); $now=time();
    if (!is_array($state) || $state['start']+HOUR_IN_SECONDS<=$now) { $state=array('start'=>$now,'count'=>0,'last'=>0); }
    if ($state['count']>=5 || ($state['last'] && $now-$state['last']<60)) { nh_ekf_finish($page,'limit'); }
    $state['count']++; $state['last']=$now; set_transient($key,$state,max(1,$state['start']+HOUR_IN_SECONDS-$now));
    $l=nh_ekf_lang(true); $body=nh_ekf_t('name',$l).': '.$name."\n".nh_ekf_t('email',$l).': '.$email."\n\n".nh_ekf_t('message',$l).":\n".$message;
    $sent=nh_ekf_mail(get_option('ekf_recipient',get_option('admin_email')),nh_ekf_t('subject',$l),$body,$email,'formsource');
    nh_ekf_finish($page,$sent ? 'ok' : 'failed');
}
