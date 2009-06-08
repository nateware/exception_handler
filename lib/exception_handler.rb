# Rescue exceptions in controllers with pretty message
module ExceptionHandler
  # Catch our internal errors, which are derived from the ErrorCode class,
  # and update the status XML accordingly.  Leave it to the other rescue
  # action pieces below to handle unknown errors (Network/IO/etc)
  def self.included(controller)
    controller.append_after_filter(:attach_success_status)
    # controller.rescue_from(ErrorCode) do |e|
    #   respond_to do |format|
    #     format.js   { render :text => e.to_clean_s, :status => 500 }
    #     format.xml  { render :xml  => e }
    #     format.html do 
    #       # flash[:error] = e.to_clean_s
    #       # render
    #       @error_ref = e.to_clean_s
    #       render :template => 'errors/default', :status => 500 
    #     end
    #   end
    # end
  end

  # This after filter is called on successful completion only. All
  # other exceptions result in triggering the above rescue_from
  # block, or one of the below rescue_action methods
  def attach_success_status
    return true unless params[:format].to_s == 'xml'
    return true if response.body.to_s =~ /<result>/  # avoid double add (bug?!)

    # Reset the start of the response object when talking XML
    # This is to provide a <status> header
    xml_body = response.body.split(/[\r\n]+/)  # line by line
    xml_header = xml_body.first =~ /^\s*<\?xml/ ? xml_body.shift : \
                '<?xml version="1.0" encoding="UTF-8"?>'

    # Reassemble the output response
    # Since we know it's always success in this situation, just hardcode
    # the XML for speed/simplicity
    response.body = xml_header +
      '<result><status><id>0</id><message>Successful completion</message></status>' +
      '<response>' + xml_body.join("\n") + '</response></result>'
  end

  # This method is called in development mode ("local"). 
  def rescue_action_locally(e)
    # Pre-catch and re-cast our accept_params error as something we recognize,
    # but only for .xml requests, since everything else needs a stack trace.
    if e.is_a? ::AcceptParams::ParamError and request.request_uri =~ /\.xml\b/
      create_error_log(e)
      render :xml => e, :status => 400, :layout => false
    else
      case e
      when ::ActionController::RoutingError, ::ActionController::UnknownAction
        # For some reason, format.xml doesn't work for "not found" requests, so have to manually handle
        if request.request_uri =~ /\.xml\b/
          render :xml => RequestError::NotFound.new, :status => 404, :layout => false
        elsif request.request_uri =~ /\.js\b/
          render :text => "Resource Not Found", :status => 404, :layout => false
        else
          super(e) # MUST call super or get weird error
        end
      else
        # Log all remaining exceptions to the database and give the user a unique
        # number. We can then look at the error_logs with this error number.
        @error_ref = create_error_log(e)

        respond_to do |format|
          format.js   { render :text => e.to_clean_s, :status => 500, :layout => false }
          # Include our <status> block, but also send a 500 to halt the client
          format.xml  { render :xml => e, :status => 500, :layout => false }
          format.html { super(e) }  # MUST call super or get weird error
        end
      end
    end
  end

  # This method is called in Production mode ("public")
  # We sanitize the error messages, printing out a unique code to the logs,
  # then show them a generic "Server Error" page.
  def rescue_action_in_public(e)
    # Pre-catch and re-cast our accept_params error as something we recognize,
    # but only for .xml requests, since everything else needs a stack trace.
    if e.is_a? ::AcceptParams::ParamError and request.request_uri =~ /\.xml\b/
      create_error_log(e)
      render :xml => e, :status => 400, :layout => false
    else
      case e
      when ::ActionController::RoutingError, ::ActionController::UnknownAction
        # For some reason, format.xml doesn't work for "not found" requests, so have to manually handle
        if request.request_uri =~ /\.xml\b/
          render :xml => e, :status => 404, :layout => false
        elsif request.request_uri =~ /\.js\b/
          render :text => "Resource Not Found", :status => 404, :layout => false
        else
          render :template => 'errors/not_found', :status => 404, :layout => 'application'
        end
      when ::ActionController::InvalidAuthenticityToken, ::RequestError::HmacValidationFailed
        # This is the error thrown by the Rails 2.x protect_from_forgery token checking
        # We want to handle it the same as our custom HMAC generation
        create_error_log(e)
        respond_to do |format|
          format.js   { render :text => "Malformed Request", :status => 400, :layout => false }
          format.xml  { render :xml  => e, :status => 400, :layout => false }
          format.html { render :template => 'errors/bad_request', :layout => 'application' }
        end
      else
        # Log all remaining exceptions to the database and give the user a unique
        # number. We can then look at the error_logs with this error number.
        @error_ref = create_error_log(e)

        # Send different content, depending on Ajax vs HTML
        respond_to do |format|
          format.html { render :template => 'errors/default', :status => 500 }
          format.js   { render :text => "Request Failed: Server Error (Reference: #{@error_ref})",
                               :status => 500, :layout => false }
          # Include our <status> block, but also send a 500 to halt the client
          format.xml { render :xml => e, :status => 500 }
        end
      end
    end
  end

  # This logs our error to a database table, so we can get to it from the admin tool
  def create_error_log(e)
    return true
    error_ref = Time.now.to_i
    ErrorLog.create(
      :error_code => e.class.name.to_s,
      :class_name => self.class.name.to_s,
      :function   => params[:action] || 'index',
      :reference  => error_ref,
      :message    => (e.message.nil? ? '' : e.message[0..1999]),
      :call_stack => (e.backtrace.nil? ? '' : e.backtrace.join("\n")[0..3999]),
      :hostname   => request.host[0..999],
      :port       => request.port,
      :url        => request.request_uri[0..1999],
      :params     => params.inspect[0..1999]
    )
    logger.error "[ERROR] [session_id=#{request.session_options[:id]}]: #{e}"
    error_ref
  end
end
